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
		enum method_type : unsigned { method, final, async };

	private:
		unsigned m_type;

		union
		{
			regular_handle_methed m_regular_ptr;
			finalizer_handle_method m_final_ptr;
			async_handle_method m_async_ptr;
		};

		ext::intrusive_ptr<ext::shared_state_basic> m_future;

	public:
		handle_method_type(std::nullptr_t ptr) noexcept : m_type(method), m_regular_ptr(ptr) {}
		handle_method_type(regular_handle_methed ptr) noexcept : m_type(method), m_regular_ptr(ptr) {}
		handle_method_type(finalizer_handle_method ptr) noexcept : m_type(final),  m_final_ptr(ptr) {}

		handle_method_type(ext::intrusive_ptr<ext::shared_state_basic> future_handle, async_handle_method ptr) noexcept
		    : m_type(async),  m_async_ptr(ptr), m_future(std::move(future_handle)) {}

		auto type() const noexcept { return m_type; }
		bool is_method() const noexcept { return m_type == method; }
		bool is_final() const noexcept { return m_type == final; }
		bool is_async() const noexcept { return m_type == async; }

		auto regular_ptr() const noexcept { return m_regular_ptr; }
		auto finalizer_ptr() const noexcept { return m_final_ptr; }
		auto async_ptr() const noexcept { return m_async_ptr; }

		auto & future() noexcept { return m_future; }
		const auto & future() const noexcept { return m_future; }
	};

	inline auto http_server::async_method(ext::intrusive_ptr<ext::shared_state_basic> future_handle, async_handle_method async_method) -> handle_method_type
	{
		return handle_method_type(std::move(future_handle), async_method);
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
		//auto task = [method, server, method_ptr = std::move(method_ptr), context = std::move(context)]()
		//{
		//	(server->*method)(std::move(method_ptr), std::move(context));
		//};
		//
		//return m_executor->submit(std::move(task));
		
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
}
