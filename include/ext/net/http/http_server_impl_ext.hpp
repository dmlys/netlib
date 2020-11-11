#include <ext/net/http/http_server.hpp>
#include <ext/reverse_lock.hpp>

// http_server additional stuff:
// internal class definitions, internal template methods, etc

namespace ext::net::http
{
	/************************************************************************/
	/*                        tasks stuff                                   */
	/************************************************************************/
	class http_server::task_base : public hook_type
	{
	public:
		virtual ~task_base() = default;

		// note: addref, release are present in ext::packaged_once_task_impl, that can issue a conflict,
		// if signature same, but return value different - it's a error.
		// just name them differently, it's internal private class.
		virtual void task_addref()  noexcept = 0;
		virtual void task_release() noexcept = 0;
		virtual void task_abandone() noexcept = 0;
		virtual void task_execute() noexcept = 0;

	public:
		friend inline void intrusive_ptr_add_ref(task_base * ptr) noexcept { ptr->task_addref(); }
		friend inline void intrusive_ptr_release(task_base * ptr) noexcept { ptr->task_release(); }
		friend inline void intrusive_ptr_use_count(const task_base * ptr) noexcept {}
	};

	template <class Functor, class ResultType>
	class http_server::task_impl : public task_base,
	                               public ext::packaged_once_task_impl<Functor, ResultType()>
	{
		using base_type = ext::packaged_once_task_impl<Functor, ResultType()>;

	public:
		void task_addref()  noexcept override { base_type::addref(); }
		void task_release() noexcept override { base_type::release(); }
		void task_abandone() noexcept override { base_type::release_promise(); }
		void task_execute() noexcept override { base_type::execute(); }

	public:
		// inherit constructors
		using base_type::base_type;

	public:
		friend inline void intrusive_ptr_add_ref(task_impl * ptr) noexcept { ptr->task_addref(); }
		friend inline void intrusive_ptr_release(task_impl * ptr) noexcept { ptr->task_release(); }
		friend inline void intrusive_ptr_use_count(const task_impl * ptr) noexcept {}
	};



	/************************************************************************/
	/*                     handle and async stuff                           */
	/************************************************************************/
	class http_server::handle_method_type
	{
	public:
		enum method_type : unsigned { null, method, final, async, wait_socket };

	private:
		unsigned m_type;
		socket_queue::wait_type m_wait_type;

		union
		{
			regular_handle_methed m_regular_ptr;
			finalizer_handle_method m_final_ptr;
		};

		ext::intrusive_ptr<ext::shared_state_basic> m_future;

	public:
		handle_method_type(std::nullptr_t ptr) noexcept : m_type(null), m_regular_ptr(ptr) {}
		handle_method_type(regular_handle_methed ptr) noexcept : m_type(ptr ? method : null), m_regular_ptr(ptr) {}
		handle_method_type(finalizer_handle_method ptr) noexcept : m_type(ptr ? final : null),  m_final_ptr(ptr) {}

		handle_method_type(ext::intrusive_ptr<ext::shared_state_basic> future_handle, regular_handle_methed ptr) noexcept
		    : m_type(ptr ? async : null),  m_regular_ptr(ptr), m_future(std::move(future_handle)) {}

		handle_method_type(socket_queue::wait_type wait_type, regular_handle_methed ptr) noexcept
		    : m_type(ptr ? wait_socket : null), m_wait_type(wait_type), m_regular_ptr(ptr) {}

		explicit operator bool() const noexcept { return m_type != null; }

		auto type() const noexcept { return m_type; }
		bool is_null() const noexcept { return m_type == null; }
		bool is_method() const noexcept { return m_type == method; }
		bool is_final() const noexcept { return m_type == final; }
		bool is_async() const noexcept { return m_type == async; }
		bool is_wait_socket() const noexcept { return m_type == wait_socket; }

		auto regular_ptr() const noexcept { return m_regular_ptr; }
		auto finalizer_ptr() const noexcept { return m_final_ptr; }

		auto & future() noexcept { return m_future; }
		const auto & future() const noexcept { return m_future; }

		auto socket_wait_type() const noexcept { return m_wait_type; }
	};

	inline auto http_server::async_method(ext::intrusive_ptr<ext::shared_state_basic> future_handle, regular_handle_methed async_method) -> handle_method_type
	{
		return handle_method_type(std::move(future_handle), async_method);
	}

	inline auto http_server::async_method(socket_queue::wait_type wait_type, regular_handle_methed async_method) -> handle_method_type
	{
		return handle_method_type(std::move(wait_type), async_method);
	}


	class http_server::delayed_async_executor_task_continuation :
	    public ext::continuation_base,
	    public hook_type
	{
		friend http_server;

		http_server * m_owner;
		handle_method_type m_method;
		processing_context * m_context;

	public:
		void continuate(shared_state_basic * caller) noexcept override;
		void abandone() noexcept;

	public:
		delayed_async_executor_task_continuation(http_server * owner, handle_method_type method, processing_context * context)
		    : m_owner(owner), m_method(std::move(method)), m_context(context) {}
	};


	class http_server::processing_executor
	{
	public:
		using method_type = void (http_server::*)(handle_method_type method_ptr, processing_context * context);

	public:
		virtual ~processing_executor() = default;
		virtual ext::future<void> submit(method_type method, http_server * server, handle_method_type method_ptr, processing_context * context) = 0;
	};

	template <class ExecutorImpl>
	class http_server::processing_executor_impl : public processing_executor
	{
		ExecutorImpl m_executor;

	public:
		virtual ext::future<void> submit(method_type method, http_server * server, handle_method_type method_ptr, processing_context * context) override;

	public:
		processing_executor_impl(ExecutorImpl executor)
		    : m_executor(std::move(executor)) {}
	};

	template <class ExecutorImpl>
	ext::future<void> http_server::processing_executor_impl<ExecutorImpl>::
	    submit(method_type method, http_server * server, handle_method_type method_ptr, processing_context * context)
	{
		return m_executor->submit(method, server, std::move(method_ptr), std::move(context));
	}


	template <class Lock, class Task>
	ext::future<std::invoke_result_t<std::decay_t<Task>>> http_server::submit_task(Lock & lk, Task && task)
	{
		using result_type = std::invoke_result_t<std::decay_t<Task>>;
		using task_type = task_impl<std::decay_t<Task>, result_type>;
		using future_type = ext::future<result_type>;

		auto task_ptr = ext::make_intrusive<task_type>(std::forward<Task>(task));
		future_type fut {task_ptr};

		m_tasks.push_back(*task_ptr.release());
		m_sock_queue.interrupt();
		m_event.notify_one();

		return fut;
	}

	template <class Task>
	ext::future<std::invoke_result_t<std::decay_t<Task>>> http_server::submit_task(Task && task)
	{
		using result_type = std::invoke_result_t<std::decay_t<Task>>;

		std::lock_guard lk(m_mutex);
		if (not m_started)
		{
			if constexpr(std::is_void_v<result_type>)
				return std::forward<Task>(task)(), ext::make_ready_future();
			else
				return ext::make_ready_future(std::forward<Task>(task)());
		}
		else
		{
			return submit_task(lk, std::forward<Task>(task));
		}
	}
	
	inline void http_server::submit_handler(handle_method_type next_method, processing_context * context)
	{
		std::lock_guard lk(m_mutex);
		return submit_handler(lk, std::move(next_method), context);
	}
	
	template <class Lock>
	void http_server::submit_handler(Lock & lk, handle_method_type next_method, processing_context * context)
	{
		if (not m_processing_executor)
		{
			auto task = std::bind(&http_server::executor_handle_runner, this, std::move(next_method), context);
			submit_task(lk, std::move(task));
		}
		else
		{
			auto fres = m_processing_executor->submit(&http_server::executor_handle_runner, this, std::move(next_method), context);
			auto handle = fres.handle();
			auto old = context->executor_state.exchange(handle.release(), std::memory_order_relaxed);
			if (old) old->release();
		}
	}

	template <class Lock>
	void http_server::process_tasks(Lock & lk)
	{
		assert(lk.owns_lock());
		auto tasks = std::move(m_tasks);
		ext::reverse_lock rlk(lk);
		while (not tasks.empty())
		{
			ext::intrusive_ptr<task_base> task_ptr(&tasks.front(), ext::noaddref);
			tasks.pop_front();
			task_ptr->task_execute();
		}
	}

	class http_server::closable_http_body : public ext::net::http::closable_http_body, public ext::intrusive_atomic_counter<closable_http_body>
	{
	public:
		virtual ~closable_http_body() = default;
		virtual ext::future<void> close() = 0;
	};
	
	/// http_server implementation of http_body_streambuf
	class http_server::http_body_streambuf_impl : public http_body_streambuf
	{
		friend http_server;
		
	protected:
		// GOAL - see ext::closable_http_body description: we must implement interruption of blocking reading from socket via close method,
		// also if there is no reading operation at all at this moment - it will be good if we complete close promise immediately.
		// so we have 2 scenarios:
		//  * there is no reading operation at the moment when close was called    -> from close method mark state to interrupted, complete close promise.
		//  * there is active reading operation at the moment when close was called -> somehow interrupt it,
		//    that reading operation/thread will complete interruption, change state of this object to interrupted and complete close promise
		//
		// IMPLEMENTATION:
		// We have ext::promise<void> as requested by interface and m_interrupt_work_flag - special atomic flag to handle interruption.
		// Whenever socket reading operation is initiated - interrupt work flag is xor'ed with 0x1 beforehand:
		//  if previous value was 0x0 - no interruption request was set -> continue reading. Flag new value is effectively 0x1.
		//  if previous value was 0x1 - interrupt request was initiated -> read nothing from socket,
		//                              change state to interrupted, report interrupt condition to client. Flag new value is effectively 0x0.
		// 
		// after reading was completed before analizing result - compare exchange interrupt work flag to 0x0, expecting 0x1:
		//  if success - no interruption request was set -> continue processing, Flag new value is 0x0.
		//  if failed  - interruption request was set    -> do no more processing, !!! complete close promise
		//               change state to interrupted, report interrupt condition to client. Flag new value is effectively 0x0.
		//
		// Whenever close is called - interrupt work flag is xor'ed with 0x1:
		//  if previous value was 0x0 - no reading operation is in progress - complete close promise. Flag new value is effectively 0x1
		//  if previous value was 0x1 - reading operation is in progress - !!! other side must complete promise. Flag new value is effectively 0x0
		//
		// NOTE: close must be called only once by owning parent object.
		//       ext::promise<void> can provide future only once, otherwise it's a error and exception will be thrown.
		// 
		
		class closable_http_body_impl : public http_server::closable_http_body
		{
			friend http_body_streambuf_impl;
			friend http_server;
			
		protected:
			std::atomic<unsigned> m_interrupt_work_flag = false;
			bool m_finished = false;    // http body is finished, no more data
			bool m_interrupted = false; // this object is interrupted any read operation will throw
			bool m_filtered;
			
			// holds &underflow_normal or &underflow_filtered
			int_type (http_body_streambuf_impl::*m_underflow_method)();
			
			ext::promise<void> m_closed_promise; // close promise
			http_server * m_server;              // owning http_server
			processing_context * m_context;      // context of this http request
			
		protected:
			void mark_working();
			void unmark_working();
			void check_interrupted();
			EXT_NORETURN void throw_interrupted();
			
		public:
			virtual ext::future<void> close() override;
			
		public:
			closable_http_body_impl(http_server * server, processing_context * context);
		};
		
	protected:
		ext::intrusive_ptr<closable_http_body_impl> m_interrupt_state;
		
	protected:
		virtual void read_parse_some();
		virtual int_type underflow_normal();
		virtual int_type underflow_filtered();
		virtual int_type underflow() override;
		
	public:
		http_body_streambuf_impl(http_server * server, processing_context * context);
		virtual ~http_body_streambuf_impl() = default;
		
		http_body_streambuf_impl(http_body_streambuf_impl &&) = default;
		http_body_streambuf_impl & operator =(http_body_streambuf_impl &&) = default;
		
		http_body_streambuf_impl(const http_body_streambuf_impl &) = delete;
		http_body_streambuf_impl & operator =(const http_body_streambuf_impl &) = delete;
	};
	
	
	
	/// http_server implementation of async_http_body_source
	class http_server::async_http_body_source_impl : public async_http_body_source
	{
		friend http_server;
		
	protected:
		// GOAL - see ext::closable_http_body description: we must implement interruption,
		// through there is no blocking read from socket, adding request into http_server for reading it not atomic, and take some time.
		// Also if there is no reading operation at all at this moment - it will be good if we complete close promise immediately.
		// so we have 2 scenarios:
		//  * there is no read_some call at the moment when close was called    -> from close method mark state to interrupted, complete close promise.
		//  * there is active processing of read_some(request scheduling) at the moment when close was called -> mark interruption state,
		//    that reading operation/thread will complete interruption, change state of this object to interrupted and complete close promise

		class closable_http_body_impl : public http_server::closable_http_body
		{
			friend async_http_body_source_impl;
			friend http_server;
			
		protected:
			std::atomic<bool> m_pending_request = false; // have pending read_some request
			std::atomic<bool> m_finished = false;        // http body is finished, no more data
			std::atomic<bool> m_interrupted = false;     // this object is interrupted any read operation will throw
			bool m_filtered;
			// holds &http_server::handle_request_filtered_async_source_body_parsing 
			//    or &http_server::handle_request_normal_async_source_body_parsing
			auto (http_server::*m_async_method)(processing_context * context) -> handle_method_type;
			
			std::size_t m_asked_size;
			ext::promise<void> m_closed_promise;
			ext::promise<chunk_type> m_read_promise;
			
			http_server * m_server;              // owning http_server
			processing_context * m_context;      // context of this http request
			
		private:
			void set_value_result(chunk_type result);
			void set_exception_result(std::exception_ptr ex);
			
		public:
			virtual ext::future<void> close() override;
			
		public:
			closable_http_body_impl(http_server * server, processing_context * context);
		};
		
	protected:
		ext::intrusive_ptr<closable_http_body_impl> m_interrupt_state;
		
	protected:
		ext::future<chunk_type> make_closed_result() const;
		
	public:
		virtual auto read_some(std::vector<char> buffer, std::size_t size = 0) -> ext::future<chunk_type> override;
		
	public:
		async_http_body_source_impl(http_server * server, processing_context * context);
		virtual ~async_http_body_source_impl() = default;
		
		async_http_body_source_impl(async_http_body_source_impl &&) = default;
		async_http_body_source_impl & operator =(async_http_body_source_impl &&) = default;
		
		async_http_body_source_impl(const async_http_body_source_impl &) = delete;
		async_http_body_source_impl & operator =(const async_http_body_source_impl &) = delete;
	};



	class http_server::http_server_control : public ext::net::http::http_server_control
	{
		processing_context * m_context;
		
	private:
		filtering_context & acquire_filtering_context();
		
	public:
		virtual void request_filter_append(std::unique_ptr<filter> filter) override;
		virtual void request_filter_prepend(std::unique_ptr<filter> filter) override;
		virtual void request_filters_clear() override;
		
		virtual void response_filter_append(std::unique_ptr<filter> filter) override;
		virtual void response_filter_prepend(std::unique_ptr<filter> filter) override;
		virtual void response_filters_clear() override;

	public:
		virtual void set_response_final()      noexcept override;
		virtual bool is_response_final() const noexcept override;
		
	public:
		virtual auto socket() const -> const ext::net::socket_streambuf & override;
		virtual auto request() -> http_request & override;
		virtual auto response() -> http_response & override;
		virtual void set_response(http_response resp) override;
		virtual void override_response(http_response resp, bool final = true) override;
		
	public:
		virtual auto get_property(std::string_view name) const -> std::optional<property> override;
		virtual void set_property(std::string_view name, property prop) override;
		
	public:
		http_server_control(processing_context * context)
		    : m_context(context) {}
	};
	
}
