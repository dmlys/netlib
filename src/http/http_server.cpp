#include <fmt/format.h>
#include <ext/itoa.hpp>
#include <ext/reverse_lock.hpp>
#include <ext/errors.hpp>
#include <ext/library_logger/logging_macros.hpp>

#include <boost/core/demangle.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include <ext/net/socket_include.hpp>
#include <ext/net/http/http_server.hpp>
#include <ext/net/http/http_server_ext.hpp>

#define LOG_FATAL(...) EXTLL_FATAL_FMT(m_logger, __VA_ARGS__)
#define LOG_ERROR(...) EXTLL_ERROR_FMT(m_logger, __VA_ARGS__)
#define LOG_WARN(...) EXTLL_WARN_FMT(m_logger, __VA_ARGS__)
#define LOG_INFO(...) EXTLL_INFO_FMT(m_logger, __VA_ARGS__)
#define LOG_DEBUG(...) EXTLL_DEBUG_FMT(m_logger, __VA_ARGS__)
#define LOG_TRACE(...) EXTLL_TRACE_FMT(m_logger, __VA_ARGS__)

//#define LOG_FATAL(f, ...) EXTLL_FATAL_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_ERROR(f, ...) EXTLL_ERROR_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_WARN(f, ...) EXTLL_WARN_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_INFO(f, ...) EXTLL_INFO_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_DEBUG(f, ...) EXTLL_DEBUG_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))
//#define LOG_TRACE(f, ...) EXTLL_TRACE_STR(m_logger, fmt::format("http_server {}, " f, fmt::ptr(this), ##__VA_ARGS__))

#define SOCK_LOG_FATAL(f, ...) EXTLL_FATAL_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_ERROR(f, ...) EXTLL_ERROR_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_WARN(f, ...) EXTLL_WARN_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_INFO(f, ...) EXTLL_INFO_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_DEBUG(f, ...) EXTLL_DEBUG_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))
#define SOCK_LOG_TRACE(f, ...) EXTLL_TRACE_STR(m_logger, fmt::format("sock={}, " f, sock.handle(), ##__VA_ARGS__))


namespace ext::net::http
{
	void http_server::delayed_async_executor_task_continuation::continuate(shared_state_basic * caller) noexcept
	{
		auto owner = m_owner;
		bool notify, running;

		if (not mark_marked())
			// http_server is destructed or destructing
			return;

		// remove ourself from m_delayed and add m_task to http_server tasks list
		{
			std::lock_guard lk(owner->m_mutex);

			auto & list = owner->m_delayed;
			auto & delayed_count = owner->m_delayed_count;
			auto & executor = owner->m_processing_executor;
			auto it = list.iterator_to(*this);
			list.erase(it);

			if (not executor)
			{
				auto task = std::bind(&http_server::executor_method_runner, owner, std::move(m_method), m_context);
				owner->submit_task(lk, std::move(task));
			}
			else
			{
				auto fres = executor->submit(&http_server::executor_method_runner, owner, std::move(m_method), m_context);
				auto handle = fres.handle();
				auto old = m_context->m_executor_state.exchange(handle.release(), std::memory_order_relaxed);
				if (old) old->release();
			}

			notify = delayed_count == 0 or --delayed_count == 0;
			running = owner->m_running;
		}

		// notify http_server if needed
		if (running) owner->m_sock_queue.interrupt();
		if (notify)  owner->m_event.notify_one();

		// we were removed from m_delayed - intrusive list,
		// which does not manage lifetime, decrement refcount
		release();
	}

	void http_server::delayed_async_executor_task_continuation::abandone() noexcept
	{
		m_method = nullptr;
	}

	void http_server::do_reset(std::unique_lock<std::mutex> & lk)
	{
		assert(lk.owns_lock());

		// clean everything,
		// close any socks and listeners
		m_listener_contexts.clear();
		m_sock_handles.clear();
		m_sock_queue.clear();
		assert(m_sock_queue.empty());

		assert(m_delayed_count == 0);
		for (auto it = m_delayed.begin(); it != m_delayed.end();)
		{
			if (not it->mark_marked())
				++m_delayed_count, ++it;
			else
			{
				auto & item = *it;
				it = m_delayed.erase(it);
				item.abandone();
				item.release();
			}
		}

		// wait until all delayed_tasks are finished
		m_event.wait(lk, [this] { return m_delayed_count == 0; });

		if (m_processing_executor)
		{
			// we must wait until all our executor tasks are finished, because those task use this http_server and it's members
			std::vector<ext::future<void>> waiting_tasks;
			std::size_t task_count = 0;
			for (auto * context : m_processing_contexts)
			{
				auto state = context->m_executor_state.exchange(nullptr, std::memory_order_relaxed);
				ext::future<void> task(ext::intrusive_ptr<ext::shared_state_basic>(state, ext::noaddref));
				if (not task.valid()) continue;

				task_count += 1;
				if (not task.cancel())
					waiting_tasks.push_back(std::move(task));
			}

			ext::reverse_lock rlk(lk);
			LOG_DEBUG("waiting executor tasks to finish, tasks = {}, cancelled = {}, waiting = {}", task_count, task_count - waiting_tasks.size(), waiting_tasks.size());
			auto all_tasks = ext::when_all(std::make_move_iterator(waiting_tasks.begin()), std::make_move_iterator(waiting_tasks.end()));
			all_tasks.wait();

			LOG_DEBUG("executor tasks are finished");
			m_processing_executor = nullptr;
		}

		// dispose pending tasks
		m_tasks.clear_and_dispose([](task_base * task)
		{
			task->task_abandone();
			task->task_release();
		});

		// and delete any processing contexts
		for (auto * context : m_processing_contexts)
			destruct_context(context), delete context;

		m_processing_contexts.clear();
		m_free_contexts.clear();
		m_state_ver = 0;

		// remove any handlers and listener contexts
		m_handlers.clear();
		m_listener_contexts.clear();
	}

	void http_server::do_start(std::unique_lock<std::mutex> & lk)
	{
		assert(lk.owns_lock());
		assert(not m_thread.joinable());
		LOG_TRACE("got start request");

		if (m_joined)
			throw std::logic_error("ext::net::http::http_server::start start misuse, have joined thread");

		if (m_started)
		{
			LOG_DEBUG("start request ignored, already started");
			return;
		}

		m_started = m_running = true;
		ext::promise<void> started_promise;
		ext::future<void> started = started_promise.get_future();
		m_thread = std::thread(&http_server::run_proc, this, std::ref(started_promise));
		lk.unlock();

		started.get();
	}

	void http_server::do_stop(std::unique_lock<std::mutex> & lk)
	{
		assert(lk.owns_lock());
		LOG_TRACE("got stop request");

		if (m_joined)
			throw std::logic_error("ext::net::http::http_server::stop stop misuse, have joined thread");

		if (not m_started)
		{
			LOG_DEBUG("stop request ignored, server not started");
			// if thread exited unexpectedly, via exception, somebody must do thread join
			if (m_thread.joinable()) m_thread.join();
			return;
		}

		m_running = false;

		{
			ext::reverse_lock rlk(lk);

			m_sock_queue.interrupt();
			m_event.notify_one();
			LOG_TRACE("interrupting internal thread");

			m_thread.join();
			LOG_TRACE("internal thread finished");
		}

		m_started = false;
	}

	void http_server::start()
	{
		std::unique_lock lk(m_mutex);
		return do_start(lk);
	}

	void http_server::stop()
	{
		std::unique_lock lk(m_mutex);
		return do_stop(lk);
	}

	void http_server::join_thread()
	{
		std::unique_lock lk(m_mutex);
		LOG_TRACE("got join_thread request");

		if (m_joined)
		{
			assert(m_started == true);
			throw std::logic_error("ext::net::http::http_server::join_thread misuse, already have joined thread");
		}
		else
		{
			if (m_started)
				throw std::logic_error("ext::net::http::http_server::join_thread misuse, already started background thread");
			else
			{
				m_started = m_running = m_joined = true;
				ext::promise<void> started_promise;
				ext::future<void> started = started_promise.get_future();

				{
					ext::reverse_lock rlk(lk);
					LOG_TRACE("joining thread");
					run_proc(started_promise);
					LOG_TRACE("run_proc finished");
				}

				m_started = m_joined = false;
				// propagate exceptions
				return started.get();
			}
		}
	}

	void http_server::interrupt()
	{
		bool joined = m_joined;
		std::atomic_thread_fence(std::memory_order_acquire);
		if (joined)
		{
			m_running = false;
			// release is done in m_sock_queue.interrupt();
			m_sock_queue.interrupt();
		}
	}

	void http_server::run_proc(ext::promise<void> & started_promise)
	{
		bool got_exception = false;
		m_threadid = std::this_thread::get_id();
		std::unique_lock lk(m_mutex);

		try
		{
			assert(m_sock_queue.empty());

			for (auto & [addr, context] : m_listener_contexts)
			{
				auto & listener = context.listener;
				if (not listener) continue;

				try
				{
					if (not listener.is_listening())
						// listen can throw exception, and in that case we should stop
						listener.listen(context.backlog);
				}
				catch (std::system_error & ex)
				{
					LOG_ERROR("exception while configuring listener {} in http_server thread: class - {}; what - {}", listener.sock_endpoint(), boost::core::demangle(typeid(ex).name()), ex.what());
					started_promise.set_exception(std::current_exception());
					got_exception = true;
					goto exit;
				}

				LOG_INFO("listening on {}", listener.sock_endpoint());
				m_sock_queue.add_listener(std::move(listener));
			}

			started_promise.set_value();

			for (;;)
			{
				process_tasks(lk);

				if (not m_running)
					break;

				if (m_sock_queue.empty())
				{
					LOG_DEBUG("empty socket_queue");
					// if theres joined thread - we should break out, m_event can't be fired from interrupt
					if (m_joined) break;

					m_event.wait(lk);
					continue;
				}
				else
				{
					ext::reverse_lock rlk(lk);
					run_sockqueue();
				}
			}
		}
		// any exception at this point is fatal, and http_server should be stopped.
		// errors from http_handlers are caught and handled earlier in appropriate places.
		catch (std::exception & ex)
		{
			got_exception = true;
			LOG_ERROR("exception in http_server thread, server stopped: class - {}; what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
		}
		catch (...)
		{
			got_exception = true;
			LOG_ERROR("unknown exception in http_server thread, server stopped");
		}

	exit:
		// tasks should be empty, unless we got exception
		EXT_UNUSED(got_exception);
		assert(got_exception or m_tasks.empty());
		m_running = false;
		do_reset(lk);
	}

	void http_server::run_sockqueue()
	{
		for (;;)
		{
			socket_queue::wait_status status;
			socket_streambuf sock;
			std::tie(status, sock) = m_sock_queue.take();

			switch (status)
			{
			    default:
			    case socket_queue::timeout:
					EXT_UNREACHABLE();

			    case socket_queue::empty_queue:
			    case socket_queue::interrupted:
				    return;

			    case socket_queue::ready:
				    break;
			}

			bool inserted;
			std::tie(std::ignore, inserted) = m_sock_handles.insert(sock.handle());
			// check if socket become ready because of error
			if (sock.last_error())
			{
				close_connection(std::move(sock));
				continue;
			}

			if (inserted)
			{
				LOG_INFO("got connection(sock={}): peer {} <-> sock {}", sock.handle(), sock.peer_endpoint_noexcept(), sock.sock_endpoint_noexcept());
			}

			// set socket operation timeout, while in sock_queue socket have m_keep_alive_timeout
			sock.timeout(m_socket_timeout);

			auto * context = acquire_context();
			if (not context)
			{
				auto response = create_server_busy_response(sock);
				postprocess_response(response);
				write_response(sock, response);
				close_connection(std::move(sock));
				continue;
			}
			else
			{
				prepare_context(context, std::move(sock), inserted);

				// run_socket will do full handling of socket, asyncly if needed:
				// * parse request
				// * process request
				// * write request
				// * place socket back into queue or close it, depending on errors/Close header
				run_socket(context);
				continue;
			}
		}
	}

	void http_server::run_socket(processing_context * context)
	{
		if (not m_processing_executor)
			executor_method_runner(&http_server::handle_request, std::move(context));
		else
		{
			auto fres = m_processing_executor->submit(&http_server::executor_method_runner, this, &http_server::handle_request, context);
			auto handle = fres.handle();
			auto old = context->m_executor_state.exchange(handle.release(), std::memory_order_relaxed);
			if (old) old->release();
		}
	}

	void http_server::executor_method_runner(handle_method_type next_method, processing_context * context)
	{
		try
		{
            again: switch (next_method.type())
			{
				default: EXT_UNREACHABLE();

				case handle_method_type::method: next_method = (this->*next_method.regular_ptr())(std::move(context)); goto again;
				case handle_method_type::final: break;
				case handle_method_type::async:
					auto ptr = next_method.future();
					if (ptr->is_pending())
						return submit_async_executor_task(std::move(ptr), std::move(next_method), std::move(context));
					else
					{
						next_method = (this->*next_method.async_ptr())(context, std::move(ptr));
						goto again;
					}
			}
		}
		catch (std::exception & ex)
		{
			context->conn_action = close;
			next_method = &http_server::handle_finish;
			LOG_ERROR("exception while processing socket = {}: class - {}; what - {}", context->sock.handle(), boost::core::demangle(typeid(ex).name()), ex.what());
		}

		auto task = std::bind(next_method.finalizer_ptr(), this, std::move(context));
		if (m_threadid == std::this_thread::get_id())
			task();
		else
		{
			submit_task(std::move(task));
		}
	}

	void http_server::submit_async_executor_task(ext::intrusive_ptr<ext::shared_state_basic> handle, handle_method_type method, processing_context * context)
	{
		if (handle->is_deferred())
			handle->wait();

		auto cont = ext::make_intrusive<delayed_async_executor_task_continuation>(this, std::move(method), std::move(context));

		{
			std::lock_guard lk(m_mutex);
			m_delayed.push_back((cont.addref(), *cont.get()));
		}

		handle->add_continuation(cont.get());
	}

	auto http_server::handle_request(processing_context * context) -> handle_method_type
	{
		if (context->ssl_ctx and not configure_accepted_socket(context->sock, std::move(context->ssl_ctx)))
			return &http_server::handle_finish;

		auto & sock = context->sock;
		{	// check if EOF
			sock.throw_errors(false);
			int next = sock.sgetc();
			sock.throw_errors(true);

			if (next == EOF) return &http_server::handle_finish;
		}

		http_parse_result parse_result;
		auto & response = context->response;
		auto & request = context->request;

		std::tie(parse_result, request) = parse_request(sock);
		// parse request will not throw exception, except some critical one, like out of memory
		switch (parse_result)
		{
		    case http_parse_result::success:
				context->conn_action = request.conn_action;
				break;

			case http_parse_result::parse_error:
				response = create_bad_request_response(sock, connection_action_type::close);
				return &http_server::handle_response;

		    case http_parse_result::socket_error:
		    default: return &http_server::handle_finish;
		}

		log_request(request);
		return &http_server::handle_prefilters;
	}

	auto http_server::handle_prefilters(processing_context * context) -> handle_method_type
	{
		try
		{
			for (auto * filter : context->prefilters)
			{
				auto res = filter->prefilter(context->request);
				if (not res) continue;

				context->response = *res;
				return &http_server::handle_response;
			}

			return &http_server::handle_processing;
		}
		catch (std::exception & ex)
		{
			LOG_WARN("pre-filters processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			context->response = create_internal_server_error_response(context->sock, context->request, &ex);
			return &http_server::handle_response;
		}
		catch (...)
		{
			LOG_ERROR("pre-filters unknown processing error");
			context->response = create_internal_server_error_response(context->sock, context->request, nullptr);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_processing(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		auto & response = context->response;
		auto & request = context->request;
		auto * handler = find_handler(*context);

		if (handler)
		{
			SOCK_LOG_INFO("found http handler {} for {} {}, processing", fmt::ptr(handler), request.method, request.url);
			response = process_request(sock, *handler, request);
		}
		else
		{
			SOCK_LOG_INFO("http handler not found for {} {}, returning 404", request.method, request.url);
			response = create_unknown_request_response(sock, request);
		}

		return &http_server::handle_processing_result;
	}

	auto http_server::handle_processing_result(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		auto & response = context->response;
		if (not std::holds_alternative<http_response>(response))
		{
			assert(std::holds_alternative<async_process_result>(response));
			auto & fresp = std::get<async_process_result>(response);
			if (fresp.is_ready() or fresp.is_deferred())
			{
				response = process_ready_response(std::move(fresp), context->sock, context->request);
			}
			else
			{
				SOCK_LOG_INFO("async http_response, scheduling async processing");
				return async_method(fresp.release(), &http_server::handle_async_processing_result);
			}
		}

		return &http_server::handle_postfilters;
	}

	auto http_server::handle_async_processing_result(processing_context * context, ext::intrusive_ptr<ext::shared_state_basic> resp_handle) -> handle_method_type
	{
		auto & sock = context->sock;
		SOCK_LOG_INFO("async http_response ready");

		context->response = ext::future<http_response>(std::move(resp_handle));
		return &http_server::handle_processing_result;
	}

	auto http_server::handle_postfilters(processing_context * context) -> handle_method_type
	{
		try
		{
			auto & resp = std::get<http_response>(context->response);
			for (auto * filter : context->postfilters)
				filter->postfilter(context->request, resp);

			return &http_server::handle_response;
		}
		catch (std::runtime_error & ex)
		{
			LOG_WARN("post-filters processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			context->response = create_internal_server_error_response(context->sock, context->request, &ex);
			return &http_server::handle_response;
		}
		catch (...)
		{
			LOG_ERROR("post-filters unknown processing error");
			context->response = create_internal_server_error_response(context->sock, context->request, nullptr);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_response(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		auto response = std::get<http_response>(std::move(context->response));
			response.conn_action = context->conn_action;
		
		postprocess_response(response);
		log_response(response);

		context->conn_action = write_response(sock, response) ? response.conn_action : close;
		return &http_server::handle_finish;
	}

	void http_server::handle_finish(processing_context * context)
	{
		assert(std::this_thread::get_id() == m_threadid);
		if (context->conn_action == close)
			close_connection(std::move(context->sock));
		else
			submit_connection(std::move(context->sock));

		release_context(context);
	}

	auto http_server::acquire_context() -> processing_context *
	{
		if (not m_free_contexts.empty())
		{
			auto * ptr = m_free_contexts.back();
			LOG_TRACE("reused context = {}, {}/{} - {}/{}", fmt::ptr(ptr), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
			m_free_contexts.pop_back();
			return ptr;
		}
		else if (m_processing_contexts.size() >= m_maximum_contexts)
		{
			LOG_TRACE("no more contexts: {}/{} - {}/{}", m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
			return nullptr;
		}
		else
		{
			auto context = std::make_unique<processing_context>();
			construct_context(context.get());
			m_processing_contexts.insert(context.get());
			LOG_TRACE("allocated new context {}, {}/{} - {}/{}", fmt::ptr(context.get()), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
			return context.release();
		}
	}

	void http_server::release_context(processing_context * context)
	{
		auto old = context->m_executor_state.exchange(nullptr, std::memory_order_relaxed);
		if (old) old->release();

		if (m_free_contexts.size() < m_minimum_contexts)
		{
			m_free_contexts.push_back(context);
			LOG_TRACE("put into reused context {}, {}/{} - {}/{}", fmt::ptr(context), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
		}
		else
		{
			m_processing_contexts.erase(context);
			std::unique_ptr<processing_context> pcontext(context);
			destruct_context(context);
			LOG_TRACE("freed context {}, {}/{} {}/{}", fmt::ptr(context), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
		}
	}

	void http_server::prepare_context(processing_context * context, socket_streambuf sock, bool newconn)
	{
		context->sock = std::move(sock);
		context->conn_action = close;

		if (m_state_ver != context->state_ver)
		{
			context->state_ver = m_state_ver;

			using boost::make_transform_iterator;
			auto get = [](const auto & sptr) { return sptr.get(); };
			auto pre_sorter = [](const http_pre_filter * ptr1, const http_pre_filter * ptr2) noexcept { return ptr1->preorder() < ptr2->preorder(); };
			auto post_sorter = [](const http_post_filter * ptr1, const http_post_filter * ptr2) noexcept { return ptr1->postorder() < ptr2->postorder(); };

			context->handlers.assign(make_transform_iterator(m_handlers.begin(), get), make_transform_iterator(m_handlers.end(), get));
			context->prefilters.assign(make_transform_iterator(m_prefilters.begin(), get), make_transform_iterator(m_prefilters.end(), get));
			context->postfilters.assign(make_transform_iterator(m_postfilters.begin(), get), make_transform_iterator(m_postfilters.end(), get));

			std::stable_sort(context->prefilters.begin(), context->prefilters.end(), pre_sorter);
			std::stable_sort(context->postfilters.begin(), context->postfilters.end(), post_sorter);
			std::reverse(context->postfilters.begin(), context->postfilters.end());
		}


		if (newconn)
		{
			const auto & listener_context = get_listener_context(context->sock);
			context->ssl_ctx = listener_context.ssl_ctx;
		}
	}

	void http_server::construct_context(processing_context * context) {}
	void http_server::destruct_context(processing_context * context) {}


	void http_server::submit_connection(socket_streambuf sock)
	{
		assert(std::this_thread::get_id() == m_threadid);

		// while awaiting new request we can be much more liberal on waiting timeout
		sock.timeout(m_keep_alive_timeout);
		m_sock_queue.submit(std::move(sock));
	}

	void http_server::close_connection(socket_streambuf sock)
	{
		assert(std::this_thread::get_id() == m_threadid);

		if (sock.last_error() == sock_errc::error)
			LOG_WARN("connection failed(sock={}): peer {} <-> sock {}; error is {}", sock.handle(), sock.peer_endpoint_noexcept(), sock.sock_endpoint_noexcept(), format_error(sock.last_error()));
		else
			LOG_INFO("connection closed(sock={}): peer {} <-> sock {}", sock.handle(), sock.peer_endpoint_noexcept(), sock.sock_endpoint_noexcept());

		m_sock_handles.erase(sock.handle());
		// when closing, we want a realy small timeout(for SSH shutdown mostly)
		sock.throw_errors(false);
		sock.timeout(m_close_socket_timeout);
		sock.close();
	}

	static bool pending_ssl_hanshake(socket_streambuf & sock)
	{
		auto handle = sock.handle();
		char ch;

		int read = ::recv(handle, &ch, 1, MSG_PEEK);
		if (read <= 0) return false;

		// SSL handshake packet starts with character 21(0x16)
		// https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html
		return ch == 0x16;
	}

	bool http_server::configure_accepted_socket(socket_streambuf & sock, ssl_ctx_iptr ssl_ctx) const
	{
#ifdef EXT_ENABLE_OPENSSL
		if (pending_ssl_hanshake(sock))
		{
			if (ssl_ctx)
			{
				sock.ssl_error_retrieve(openssl::error_retrieve::peek);
				sock.throw_errors(false);
				bool accepted = sock.accept_ssl(ssl_ctx.get());
				sock.throw_errors(true);

				if (accepted)
				{
					SOCK_LOG_INFO("accepted SSL connection");
					return true;
				}
				else
				{
					SOCK_LOG_WARN("SSL failure: {}", format_error(sock.last_error()));
					return false;
				}
			}
			else
			{
				SOCK_LOG_WARN("peer requested SSL session, but server is not configured to serve SSL on that listener, closing connection");
				return false;
			}
		}
		else
		{
			if (ssl_ctx)
			{
				SOCK_LOG_WARN("peer does not requested SSL session, but server is configured to serve SSL on that listener, closing connection");
				return false;
			}
			else
			{
				return true;
			}
		}
#else
		return true;
#endif
	}

	auto http_server::parse_request(socket_streambuf & sock) const -> std::tuple<http_parse_result, http_request>
	{
		http_request request;

		try
		{
			http_parser parser(http_parser::request);
			parser.parse_url(sock, request.url);
			request.method = parser.http_method();
			request.http_version = parser.http_version();

			std::string name, value;
			while (parser.parse_header(sock, name, value))
				request.headers.push_back({std::move(name), std::move(value)});

			static_assert(connection_action_type::close == 1 and connection_action_type::keep_alive == 2);
			request.conn_action = static_cast<connection_action_type>(1 + static_cast<unsigned>(parser.should_keep_alive()));
			parser.parse_body(sock, request.body);
			return std::make_tuple(success, std::move(request));
		}
		catch (std::system_error & ex)
		{
			LOG_WARN("got system error while processing request: {}", format_error(ex.code()));
			return std::make_tuple(socket_error, std::move(request));
		}
		catch (std::runtime_error & ex)
		{
			LOG_WARN("got parsing error while processing request: {}; socket status: {}",
			         ex.what(), format_error(sock.last_error()));

			return std::make_tuple(parse_error, std::move(request));
		}
	}

	bool http_server::write_response(socket_streambuf & sock, const http_response & resp) const
	{
		try
		{
			assert(sock.throw_errors());

			write_http_response(sock, resp, true);
			sock.pubsync();

			assert(sock.is_valid());
			return resp.conn_action == keep_alive;
		}
		catch (std::system_error & ex)
		{
			assert(ex.code() == sock.last_error());
			LOG_WARN("response sending failure: {}", format_error(sock.last_error()));
			return false;
		}
	}

	void http_server::postprocess_response(http_response & resp) const
	{
		if (resp.conn_action == close)
			set_header(resp.headers, "Connection", "close");

		if (resp.body.size() != 0 or resp.conn_action != close)
			set_header(resp.headers, "Content-Length", std::to_string(resp.body.size()));
	}

	auto http_server::process_request(socket_streambuf & sock, const http_server_handler & handler, http_request & request) -> process_result
	{
		try
		{
			return handler.process(request);
		}
		catch (std::exception & ex)
		{
			LOG_WARN("processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			return create_internal_server_error_response(sock, request, &ex);
		}
		catch (...)
		{
			LOG_ERROR("unknown processing error");
			return create_internal_server_error_response(sock, request, nullptr);
		}
	}

	auto http_server::process_ready_response(async_process_result result, socket_streambuf & sock, http_request & request) -> http_response
	{
		try
		{
			if (result.is_abandoned())
				return create_processing_abondoned_response(sock, request);
			
			if (result.is_cancelled())
				return create_processing_cancelled_response(sock, request);
			
			return result.get();
		}
		catch (std::exception & ex)
		{
			LOG_WARN("processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			return create_internal_server_error_response(sock, request, &ex);
		}
		catch (...)
		{
			LOG_ERROR("unknown processing error");
			return create_internal_server_error_response(sock, request, nullptr);
		}
	}

	auto http_server::get_listener_context(const socket_streambuf & sock) const -> const listener_context &
	{
		std::string addr = sock.peer_endpoint();
		auto it = m_listener_contexts.find(addr);
		if (it == m_listener_contexts.end())
		{
			addr = "0.0.0.0";
			addr += ":";
			ext::itoa_buffer<unsigned short> buffer;
			addr += ext::itoa(sock.sock_port(), buffer);

			it = m_listener_contexts.find(addr);
		}

		assert(it != m_listener_contexts.end());
		return it->second;
	}

	auto http_server::find_handler(processing_context & context) const -> const http_server_handler *
	{
		for (auto & handler : context.handlers)
			if (handler->accept(context.request, context.sock))
				return handler;

		return nullptr;
	}

	static socket_streambuf & operator <<(socket_streambuf & sock, std::string_view str)
	{
		sock.sputn(str.data(), str.size());
		return sock;
	}

	static socket_streambuf & operator <<(socket_streambuf & sock, std::size_t num)
	{
		ext::itoa_buffer<decltype(num)> buffer;
		sock << ext::itoa(num, buffer);
		return sock;
	}

	static std::string http_version_string(int version)
	{
		std::string str;
		ext::itoa_buffer<int> buffer;

		str.reserve(10);
		str += "HTTP/";
		str += ext::itoa(version / 10, buffer);
		str += ".";
		str += ext::itoa(version % 10, buffer);

		return str;
	}

	void http_server::log_request(const http_request & request) const
	{
		if (not m_logger) return;

		static_assert(ext::library_logger::Trace > ext::library_logger::Debug);
		auto log_level = std::min(m_request_logging_level, m_request_body_logging_level);

		auto record = m_logger->open_record(log_level, __FILE__, __LINE__);
		if (not record) return;

		auto & stream = record.get_ostream();
		stream << fmt::format("logging http request:\n", fmt::ptr(this));
		write_http_request(stream, request, m_logger->is_enabled_for(m_request_body_logging_level));

		record.push();
	}

	void http_server::log_response(const http_response & response) const
	{
		if (not m_logger) return;

		static_assert(ext::library_logger::Trace > ext::library_logger::Debug);
		auto log_level = std::min(m_request_logging_level, m_request_body_logging_level);

		auto record = m_logger->open_record(log_level, __FILE__, __LINE__);
		if (not record) return;

		auto & stream = record.get_ostream();
		stream << fmt::format("logging http response:\n", fmt::ptr(this));
		write_http_response(stream, response, m_logger->is_enabled_for(m_request_body_logging_level));

		record.push();
	}

	std::string http_server::format_error(std::error_code errc) const
	{
#ifdef EXT_ENABLE_OPENSSL
		if (errc != sock_errc::ssl_error)
			return ext::format_error(errc);
		else
		{
			// if no errors in queue, print errc as is
			if (not openssl::last_error(openssl::error_retrieve::peek))
				return ext::format_error(errc);

			// print_error_queue effectively clears openssl error queue
			auto output = openssl::print_error_queue();
			// indent output by \t, so in log it would not be mixed with other records
			output.insert(0, "openssl error;\n\t");
			boost::algorithm::replace_all(output, "\n", "\n\t");

			return output;
		}
#else
		return ext::format_error(errc);
#endif
	}

	http_response http_server::create_bad_request_response(socket_streambuf &sock, connection_action_type conn /*= close*/) const
	{
		http_response response;
		response.http_code = 400;
		response.status = response.body = "BAD REQUEST";
		response.conn_action = conn;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_server_busy_response(socket_streambuf & sock, connection_action_type conn /*= close*/) const
	{
		http_response response;
		response.http_code = 503;
		response.status = "Service Unavailable";
		response.body = "Server is busy, too many requests. Repeat later";
		response.conn_action = conn;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_unknown_request_response(socket_streambuf & sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 404;
		response.status = response.body = "Not found";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_processing_abondoned_response(socket_streambuf & sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 500;
		response.status = "Internal Server Error";
		response.body = "Request processing abandoned";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_processing_cancelled_response(socket_streambuf & sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 404;
		response.status = "Cancelled";
		response.body = "Request processing cancelled";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_internal_server_error_response(socket_streambuf & sock, const http_request & request, std::exception * ex) const
	{
		http_response response;
		response.http_code = 500;
		response.status = response.body = "Internal Server Error";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	auto http_server::get_socket_timeout() const -> duration_type
	{
		std::unique_lock lk(m_mutex);
		return m_socket_timeout;
	}

	void http_server::set_socket_timeout(duration_type timeout)
	{
		submit_task([this, timeout]
		{
			m_socket_timeout = timeout;
		});
	}

	auto http_server::get_keep_alive_timeout() const -> duration_type
	{
		std::unique_lock lk(m_mutex);
		return m_keep_alive_timeout;
	}

	void http_server::set_keep_alive_timeout(duration_type timeout)
	{
		submit_task([this, timeout]
		{
			m_keep_alive_timeout = timeout;
			m_sock_queue.set_default_timeout(m_keep_alive_timeout);
		});
	}

	auto http_server::do_add_listener(listener listener, int backlog, ssl_ctx_iptr ssl_ctx) -> ext::future<void>
	{
		//assert(listener.is_bound());
		std::unique_lock lk(m_mutex);
		if (m_started)
		{
			auto task = [this, listener = std::move(listener), backlog, ssl_ctx = std::move(ssl_ctx)]() mutable
			{
				auto addr = listener.sock_endpoint();
				listener_context context;
				context.backlog = backlog > 0 ? backlog : m_default_backlog;
				context.ssl_ctx = std::move(ssl_ctx);

				bool inserted;
				std::tie(std::ignore, inserted) = m_listener_contexts.emplace(addr, std::move(context));
				if (not inserted)
				{
					auto err_msg = fmt::format("can't add listener on {}, already have one", addr);
					LOG_ERROR("can't add listener on {}, already have one", addr);
					throw std::runtime_error(err_msg);
				}

				if (not listener.is_listening())
					listener.listen(context.backlog);

				LOG_INFO("listening on {}", addr);
				m_sock_queue.add_listener(std::move(listener));
			};

			return submit_task(lk, std::move(task));
		}
		else
		{
			auto addr = listener.sock_endpoint();
			listener_context context;
			context.backlog = backlog > 0 ? backlog : m_default_backlog;
			context.listener = std::move(listener);
			context.ssl_ctx = std::move(ssl_ctx);

			bool inserted;
			std::tie(std::ignore, inserted) = m_listener_contexts.emplace(addr, std::move(context));

			if (not inserted)
			{
				auto err_msg = fmt::format("can't add listener on {}, already have one", addr);
				LOG_ERROR("can't add listener on {}, already have one", addr);
				return ext::make_exceptional_future<void>(std::runtime_error(err_msg));
			}

			return ext::make_ready_future();
		}
	}

	void http_server::do_add_handler(std::unique_ptr<const http_server_handler> handler)
	{
		m_handlers.push_back(std::move(handler));
		m_state_ver += 1;
	}

	void http_server::do_add_filter(ext::intrusive_ptr<http_filter_base> filter)
	{
		filter->set_logger(m_logger);

		if (auto ptr = ext::dynamic_pointer_cast<http_pre_filter>(filter))
			m_prefilters.push_back(std::move(ptr));

		if (auto ptr = ext::dynamic_pointer_cast<http_post_filter>(filter))
			m_postfilters.push_back(std::move(ptr));

		m_state_ver += 1;
	}

	void http_server::add_filter(ext::intrusive_ptr<http_filter_base> filter)
	{
		submit_task([this, filter = std::move(filter)]() mutable
		{
			return do_add_filter(std::move(filter));
		});
	}

	void http_server::add_handler(std::unique_ptr<const http_server_handler> handler)
	{
		submit_task([this, handler = std::move(handler)]() mutable
		{
			return do_add_handler(std::move(handler));
		});
	}

	void http_server::add_handler(std::vector<std::string> methods, std::string url, function_type function)
	{
		return add_handler(std::make_unique<simple_http_server_handler>(std::move(methods), std::move(url), std::move(function)));
	}

	void http_server::add_handler(std::string url, function_type function)
	{
		return add_handler(std::vector<std::string>(), std::move(url), std::move(function));
	}

	void http_server::add_handler(std::string method, std::string url, function_type function)
	{
		return add_handler(std::vector<std::string>{std::move(method)}, std::move(url), std::move(function));
	}

	void http_server::add_listener(listener listener, ssl_ctx_iptr ssl_ctx)
	{
		return add_listener(std::move(listener), 0, std::move(ssl_ctx));
	}

	void http_server::add_listener(unsigned short port, ssl_ctx_iptr ssl_ctx)
	{
		listener listener;
		ext::packaged_task<void()> task = [port, &listener] { listener.bind(port); };
		auto fres = task.get_future();

		if (task(); fres.has_exception())
			return fres.get();

		return add_listener(std::move(listener), std::move(ssl_ctx));
	}

	void http_server::add_listener(listener listener, int backlog, ssl_ctx_iptr ssl_ctx)
	{
		return do_add_listener(std::move(listener), backlog, std::move(ssl_ctx)).get();
	}

	void http_server::add_listener(unsigned short port, int backlog, ssl_ctx_iptr ssl_ctx)
	{
		listener listener;
		ext::packaged_task<void()> task = [port, &listener] { listener.bind(port); };
		auto fres = task.get_future();

		if (task(); fres.has_exception())
			return fres.get();

		return add_listener(std::move(listener), backlog, std::move(ssl_ctx));
	}

	void http_server::set_processing_context_limits(std::size_t minimum, std::size_t maximum)
	{
		if (minimum == 0 or maximum == 0 or minimum > maximum)
			throw std::invalid_argument(fmt::format("ext::net::http_server::set_processing_context_limits: bad limits {}/{}", minimum, maximum));

		submit_task([this, minimum, maximum]
		{
			m_minimum_contexts = minimum;
			m_maximum_contexts = maximum;
		});
	}

	void http_server::set_processing_executor(std::shared_ptr<processing_executor> executor)
	{
		std::lock_guard lk(m_mutex);

		if (m_started)
			throw std::logic_error("ext::net::http::http_server::set_processing_executor: can't set processing executor on running instance");

		m_processing_executor = nullptr;
		m_processing_executor = std::move(executor);
	}

	void http_server::set_thread_pool(std::shared_ptr<ext::thread_pool> pool)
	{
		using executor_type = processing_executor_impl<std::shared_ptr<ext::thread_pool>>;
		auto executor = std::make_shared<executor_type>(std::move(pool));
		set_processing_executor(std::move(executor));
	}

	http_server::http_server() = default;
	http_server::~http_server()
	{
		std::unique_lock lk(m_mutex);
		if (m_started)
		{
			do_stop(lk);
			assert(lk.owns_lock());
		}

		do_reset(lk);
	};
}
