#include <ext/net/http/http_server.hpp>
#include <ext/reverse_lock.hpp>

// http_server additional stuff:
// internal class definitions, internal template methods, etc

namespace ext::net::http
{
	/************************************************************************/
	/*                    http_server_control stuff                         */
	/************************************************************************/
	class http_server::http_server_control : public ext::net::http::http_server_control
	{
		processing_context * m_context;
		
	private:
		filtering_context & acquire_filtering_context();
		property_map & acquire_property_map();
		
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
		virtual auto socket() const -> socket_handle_type override;
		virtual auto request() -> http_request & override;
		virtual auto response() -> http_response & override;
		
		virtual void set_response(http_response && resp) override;
		virtual void override_response(http_response && resp, bool final = true) override;
		virtual void override_response(null_response_type) override;
		
	public:
		virtual auto get_property(std::string_view name) const -> std::optional<property> override;
		virtual void set_property(std::string_view name, property prop) override;
		
	public:
		http_server_control(processing_context * context) noexcept
		    : m_context(context) {}
		
		http_server_control(http_server_control && ) = delete;
		http_server_control & operator =(http_server_control && ) = delete;
	};
	
	
	/************************************************************************/
	/*                  http_server contexts definitions                    */
	/************************************************************************/
	
	/// Groups some context parameters for processing http request.
	/// Note that this context is bound to a socket whole lifetime,
	/// because of SSL session object and read buffer.
	/// 1st one holds current SSL session and can't be rebound to other socket
	/// 2nd can hold data from next HTTP request read on last recv operation(like http pipelining extension)
	struct http_server::processing_context
	{
		// not even movable, currently we do not move/copy functionality,
		// even more because of some members - move operation requires additional code, if even possible
		processing_context(processing_context && ) = delete;
		processing_context & operator =(processing_context && ) = delete;
		
		processing_context() = default;
		
		
		/// http_server control object associated with this context/request
		http_server::http_server_control control{this};
		
		ext::net::socket_uhandle sock; // socket where http request came from
		ssl_iptr ssl_ptr = nullptr;    // ssl session, created from listener ssl context
		
		// socket waiting
		socket_queue::wait_type wait_type;
		// next method after socket waiting is complete
		regular_handle_methed next_method;
		// current method that is executed
		regular_handle_methed cur_method;
		
		// function state used by some handle_methods, value for switch
		unsigned async_state = 0;
		// should this connection be closed after request processed, determined by Connection header,
		// but if there were errors while processing request - connection will be closed.
		connection_action_type conn_action = connection_action_type::close;
		
		// byte counters, used in various scenarios
		std::size_t read_count;    // number of total bytes read from socket, used to track maximum_http_body_size and others limits
		std::size_t written_count; // number of bytes written to socket from buffer
		// counters for input_buffer, how much was read from socket, how much was already parsed/consumed
		unsigned input_first, input_last;
		
		http_server_utils::nonblocking_http_parser parser; // http parser with state
		http_server_utils::nonblocking_http_writer writer; // http writer with state
		
		// buffer holding data read from socket, request will be parsed from here
		std::vector<char> input_buffer;
		// buffers for filtered and non filtered parsing and writting
		std::vector<char> request_raw_buffer, request_filtered_buffer;
		std::vector<char> response_raw_buffer, response_filtered_buffer;
		std::string chunk_prefix; // buffer for preparing and holding chunk prefix(chunked transfer encoding)
		
		// contexts for filtering request/reply http_body;
		std::unique_ptr<filtering_context> filter_ctx;
		std::unique_ptr<property_map> prop_map;
		
		http_request request;                    // current http request,  valid after is was parsed
		process_result response = null_response; // current http response, valid after handler was called
		
		std::shared_ptr<const config_context> config; // http server config snapshot
		const http_server_handler * handler;          // found handler for request
		
		bool have_tls_session;         // this connection have tls session
		bool expect_extension;         // request with Expect: 100-continue header, see RFC7231 section 5.1.1.
		bool continue_answer;          // context holds answer 100 Continue
		bool first_response_written;   // wrote first 100-continue
		bool final_response_written;   // wrote final(possibly second) response
		
		bool response_is_final;        // response was marked as final, see http_server_control
		bool response_is_null;         // response was set to null, no response should be sent, connection should be closed
		
		bool shutdown_socket;          // socket should be shutdowned before closing(this is regular flow, counter to network exceptional/error flow)
		bool socket_have_eof;          // socket have no more data - eof, it was probably shutdowned(or closed) by peer
		
		std::atomic<ext::shared_state_basic *> executor_state = nullptr;      // holds current pending processing execution task state, used for internal synchronization
		std::atomic<ext::shared_state_basic *> async_task_state = nullptr;    // holds current pending async operation(from handlers), used for internal synchronization
		
		// async_http_body_source/http_body_streambuf closing closer
		// allowed values:
		//   0x00 - no body closer
		//   0x01 - http_server is closing, already set body closer is taken, new should not be installed
		//   other - some body closer
		std::atomic_uintptr_t body_closer = 0;
	};
	
	/// holds some configuration parameters sharable by processing contexts
	struct http_server::config_context
	{
		/// Http filters, handlers can added when http server already started. What if we already processing some request and handler is added?
		/// When processing starts context holds snapshot of currently registered handlers and filters - only they are used; it also handles multithreaded issues.
		/// Whenever filters, handlers or anything config related changes -> new context as copy of current is created with dirty set to true.
		/// Sort of copy on write
		unsigned dirty = true;
		
		std::vector<const http_server_handler *> handlers;       // http handlers registered in server
		std::vector<const http_prefilter *>      prefilters;     // http prefilters  registered in server, sorted by order
		std::vector<const http_postfilter *>     postfilters;    // http postfilters registered in server, sorted by order
		
		/// Maximum total(per request) bytes read from socket while parsing HTTP request headers, -1 - unlimited.
		/// If request headers are not parsed yet, and server read from socket more than maximum_http_headers_size, BAD request is returned
		unsigned maximum_http_headers_size = -1;
		/// Maximum bytes(per request) read from socket while parsing HTTP body, -1 - unlimited.
		/// This affects only simple std::vector<char>/std::string bodies, and never affects stream/async bodies.
		/// If server read from socket more than maximum_http_body_size, BAD request is returned
		unsigned maximum_http_body_size = -1;
		/// Maximum bytes read from socket while parsing discarded HTTP request, -1 - unlimited.
		/// If there is no handler for this request, or some other error code is answered(e.g. unauthorized),
		/// this request is considered to be discarded - in this case we still might read it's body,
		/// but no more than maximum_discarded_http_body_size, otherwise connection is forcibly closed.
		unsigned maximum_discarded_http_body_size = -1;
	};
	
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
	
	/************************************************************************/
	/*                 stream and async source stuff                        */
	/************************************************************************/
	class http_server::closable_http_body : public ext::net::http::closable_http_body, public ext::intrusive_atomic_counter<closable_http_body>
	{
	public:
		virtual ~closable_http_body() = default;
		virtual ext::future<void> close() = 0;
		virtual bool is_finished() const noexcept = 0;
	};
	
	
	
	/// http_server implementation of http_body_streambuf
	class http_server::http_body_streambuf_impl : public http_body_streambuf
	{
		friend http_server;
		
	protected:
		// GOAL - see ext::closable_http_body description: we must implement interruption of blocking reading from socket via close method,
		// also if there is no reading operation at all at this moment - it will be good if we complete close promise immediately.
		// so we have 2 scenarios:
		//  * there is no reading operation at the moment when close was called     -> from close method mark state to interrupted, complete close promise.
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
			std::atomic<bool>     m_finished = false;    // http body is finished, no more data
			
			bool m_closed = false; // this object is interrupted, any read operation will throw
			bool m_filtered;       // this object is filtered(http body filters)
			
			// holds &underflow_normal or &underflow_filtered
			int_type (http_body_streambuf_impl::*m_underflow_method)();
			// buffer for holding stream served data,
			// this is what client will read from this stream
			std::vector<char> m_data;
			
			ext::promise<void> m_closed_promise; // close promise
			http_server * m_server;              // owning http_server
			processing_context * m_context;      // context of this http request
			
		protected:
			void mark_working();
			void unmark_working();
			void check_interrupted();
			void unwinding_unmark_working();
			EXT_NORETURN void throw_interrupted();
			
		public:
			virtual ext::future<void> close() override;
			virtual bool is_finished() const noexcept override { return m_finished.load(std::memory_order_relaxed); }
			
		public:
			closable_http_body_impl(http_server * server, processing_context * context);
		};
		
	protected:
		ext::intrusive_ptr<closable_http_body_impl> m_interrupt_state;
		
	protected:
		// 0x1 - readable, 0x2 - writable
		virtual bool wait_state(socket_handle_type sock, std::error_code & errc, time_point until, unsigned state);
		virtual bool read_some(char * data, int len, int & read, std::error_code & errc);
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
		// GOAL - see ext::closable_http_body description: we must implement interruption of current pending async operation on close
		// This is done by holding current state flags in atomic variable, see method implementations
		
		class closable_http_body_impl : public http_server::closable_http_body
		{
			friend async_http_body_source_impl;
			friend http_server;
			
		protected:
			static constexpr unsigned pending_request_mask = 0x01 << 0; // have pending read_some request
			static constexpr unsigned result_mask          = 0x01 << 1; // result is already set/is set right now
			static constexpr unsigned closed_mask          = 0x01 << 2; // this object is closed any read operation will throw
			static constexpr unsigned finished_mask        = 0x01 << 3; // http body is finished, no more data
			
			std::atomic_uint m_state_flags = 0;
			bool m_filtered;
			
			// holds &http_server::handle_request_filtered_async_source_body_parsing 
			//    or &http_server::handle_request_normal_async_source_body_parsing
			auto (http_server::*m_async_method)(processing_context * context) -> handle_method_type;
			
			std::size_t m_asked_size;            // size asked by read_some operation
			std::size_t m_default_buffer_size;   // default buffer size, used only for filtering case
			ext::promise<chunk_type> m_read_promise;
			
			http_server * m_server;              // owning http_server
			processing_context * m_context;      // context of this http request
			
		private:
			closed_exception make_closed_exception() const;
			ext::future<chunk_type> make_closed_result() const;
			
			auto take_result_promise() -> std::optional<ext::promise<chunk_type>>;
			void set_value_result(chunk_type result);
			void set_exception_result(std::exception_ptr ex);
			
		public:
			virtual ext::future<void> close() override;
			virtual bool is_finished() const noexcept override { return m_state_flags.load(std::memory_order_relaxed) & finished_mask; }
			
		public:
			closable_http_body_impl(http_server * server, processing_context * context);
		};
		
	protected:
		ext::intrusive_ptr<closable_http_body_impl> m_interrupt_state;
		
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
}
