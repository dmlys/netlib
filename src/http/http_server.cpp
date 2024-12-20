#include <ext/itoa.hpp>
#include <ext/reverse_lock.hpp>
#include <ext/errors.hpp>
#include <ext/strings/aci_string.hpp>
#include <ext/functors/ctpred.hpp>
#include <ext/hexdump.hpp>

#include <ext/stream_filtering/filtering.hpp>

#include <boost/core/demangle.hpp>
#include <boost/preprocessor/if.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include <ext/net/socket_include.hpp>
#include <ext/net/http/http_server.hpp>
#include <ext/net/http/http_server_impl_ext.hpp>
#include <ext/net/http/http_server_logging_helpers.hpp>


#ifdef NDEBUG
#define IS_RELEASE 1
#else
#define IS_RELEASE 0
#endif

#define VECTOR_FRONT_IMPL_RELEASE(vector) &vector.front()
#define VECTOR_FRONT_IMPL_DEBUG(vector) not vector.empty() ? &vector.front() : nullptr

#define VECTOR_BACK_IMPL_RELEASE(vector) &vector.back()
#define VECTOR_BACK_IMPL_DEBUG(vector) not vector.empty() ? &vector.back() : nullptr

#define VECTOR_FRONT(vector) BOOST_PP_IIF(IS_RELEASE, VECTOR_FRONT_IMPL_RELEASE, VECTOR_FRONT_IMPL_DEBUG) (vector)
#define VECTOR_BACK(vector)  BOOST_PP_IIF(IS_RELEASE, VECTOR_BACK_IMPL_RELEASE,  VECTOR_BACK_IMPL_DEBUG)  (vector)



namespace ext::net::http
{
	const std::error_code http_server::success_errc;
	
	template <class Type>
	inline static void release_atomic_ptr(std::atomic<Type *> & pointer)
	{
		auto old = pointer.exchange(nullptr, std::memory_order_relaxed);
		if (old) ext::intrusive_ptr_release(old);
	}
	
	template <class Type>
	inline static void release_atomic_ptr(std::atomic<std::uintptr_t> & pointer)
	{
		auto old = pointer.exchange(0, std::memory_order_relaxed);
		if (old <= 0x01) return;
		
		ext::intrusive_ptr_release(reinterpret_cast<Type *>(old));
	}
	
	template <class Type>
	class auto_release_atomic_ptr
	{
		std::atomic<Type *> * pointer;
	
	public:
		auto_release_atomic_ptr(std::atomic<Type *> & ptr) : pointer(&ptr) {}
		~auto_release_atomic_ptr() { release_atomic_ptr(*pointer); }
	};
	
	template <class Type1, class Type2>
	static inline bool limit_exceeded(Type1 n, Type2 limit)
	{
		return limit != -1 and n > limit;
	}
	
	void http_server::delayed_async_executor_task_continuation::continuate(shared_state_basic * caller) noexcept
	{
		if (not mark_marked())
			// http_server is destructed or destructing
			return;
		
		// remove ourself from m_delayed and add m_task to http_server tasks list
		{
			std::lock_guard lk(m_owner->m_mutex);
			
			auto & list = m_owner->m_delayed;
			auto & delayed_count = m_owner->m_delayed_count;
			auto it = list.iterator_to(*this);
			list.erase(it);
			
			m_owner->submit_handler(lk, std::move(m_method), m_context);
			
			bool notify = delayed_count == 0 or --delayed_count == 0;
			bool running = m_owner->m_running;
			
			// Notify http_server if needed
			// NOTE: Notify have to be done under lock,
			//  otherwise this http_server object can be destroyed between release of mutex and interrupt/notify_one call,
			//  and m_owner becomes dangling pointer, and call to m_sock_queue.interrupt(), m_event.notify_one() are ill-formed.
			//  While this situation is very rare - it can happen.
			//  See do_reset method and destructor.
			if (running) m_owner->m_sock_queue.interrupt();
			if (notify)  m_owner->m_event.notify_one();
		}

		// we were removed from m_delayed - intrusive list,
		// who does not manage lifetime, decrement refcount
		release();
	}

	void http_server::delayed_async_executor_task_continuation::abandone() noexcept
	{
		// This method is called only after this task is marked -> can't be ran/completed in concurrent,
		// so it's safe to use at least some of it's contents
		if (m_method.is_async())
			m_method.future()->cancel();
		
		m_method = nullptr;
	}

	void http_server::destruct()
	{
		if (m_destructed)
			return;
		
		std::unique_lock lk(m_mutex);
		if (m_started)
			do_stop(lk);
		else
		{
			// if was not started - do not log in reset method on destruction,
			// we already stopped earlier(or did not run at all)
			m_logger = nullptr;
			do_reset(lk);
		}
		
		m_destructed = true;
	}
	
	void http_server::do_reset(std::unique_lock<std::mutex> & lk)
	{
		assert(lk.owns_lock());
		assert(m_running == false);
		LOG_DEBUG("stopping and cleaning server state");
		
		
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
		
		std::vector<ext::future<void>> waiting_tasks;
		waiting_tasks.reserve(m_processing_contexts.size());
		
		{ // close(and interrupt) any http_body stream/source
			for (auto * context : m_processing_contexts)
			{
				auto state = context->body_closer.exchange(1, std::memory_order_relaxed);
				if (state <= 0x01) continue;
			
				ext::intrusive_ptr state_ptr(reinterpret_cast<http_server::closable_http_body *>(state), ext::noaddref);
				waiting_tasks.push_back(state_ptr->close());
			}
			
			ext::reverse_lock rlk(lk);
			LOG_DEBUG("waiting http_body streams and source to close, contexts = {}, waiting = {}", m_processing_contexts.size(), waiting_tasks.size());
			auto all_tasks = ext::when_all(std::make_move_iterator(waiting_tasks.begin()), std::make_move_iterator(waiting_tasks.end()));
			all_tasks.wait();
			
			waiting_tasks.clear();
			LOG_DEBUG("http_body streams and source are closed");
		}
		
		if (m_processing_executor)
		{
			// we must wait until all our executor tasks are finished, because those task use this http_server and it's members
			std::size_t task_count = 0;
			for (auto * context : m_processing_contexts)
			{
				auto state = context->executor_state.exchange(nullptr, std::memory_order_relaxed);
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
			waiting_tasks.clear();

			LOG_DEBUG("executor tasks are finished");
			m_processing_executor = nullptr;
		}
		
		// cancel pending async handlers, we will not process them anyway
		for (auto * context : m_processing_contexts)
		{
			//auto state = context->async_task_state.load(std::memory_order_relaxed);
			auto state = context->async_task_state.exchange(nullptr, std::memory_order_relaxed);
			if (not state) continue;
			
			ext::intrusive_ptr state_ptr(state, ext::noaddref);
			state->cancel();
		}

		// dispose pending tasks
		m_tasks.clear_and_dispose([](task_base * task)
		{
			task->task_abandone();
			task->task_release();
		});

		
		m_sock_queue.clear();
		m_listener_contexts.clear();
		assert(m_sock_queue.empty());
		
		
		for (auto * context : m_processing_contexts)
			context->sock.reset();
		
		// and delete any processing contexts
		for (auto * context : m_processing_contexts)
			destroy_context(context);

		m_processing_contexts.clear();
		m_free_contexts.clear();

		// remove any handlers
		do_clear_config(lk);
	}

	void http_server::do_clear_config(std::unique_lock<std::mutex> & lk)
	{
		// at this point there should not be any references except ours
		//assert(m_config_context.unique());
		for (auto * handler : m_config_context->handlers)
			delete handler;
		
		for (auto * filter : m_config_context->prefilters)
			intrusive_ptr_release(ext::unconst(filter));
		
		for (auto * filter : m_config_context->postfilters)
			intrusive_ptr_release(ext::unconst(filter));
		
		m_config_context->handlers.clear();
		m_config_context->prefilters.clear();
		m_config_context->postfilters.clear();
	}

	void http_server::do_start(std::unique_lock<std::mutex> & lk)
	{
		assert(lk.owns_lock());
		assert(not m_thread.joinable());
		LOG_DEBUG("got start request");

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
		LOG_DEBUG("got stop request");

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
			LOG_DEBUG("interrupting internal thread");

			m_thread.join();
			LOG_DEBUG("internal thread finished");
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

	void http_server::join()
	{
		std::unique_lock lk(m_mutex);
		LOG_DEBUG("got join request");

		if (m_joined)
		{
			assert(m_started == true);
			throw std::logic_error("ext::net::http::http_server::join misuse, already have joined thread");
		}
		else
		{
			if (m_started)
				throw std::logic_error("ext::net::http::http_server::join misuse, already started background thread");
			else
			{
				m_started = m_running = m_joined = true;
				bool interrupted = std::exchange(m_interrupted, false);
				std::atomic_signal_fence(std::memory_order_acq_rel);
				if (interrupted)
				{
					m_started = m_running = m_joined = false;
					LOG_DEBUG("won't join thread, got interrupt request");
					return;
				}
				
				ext::promise<void> started_promise;
				ext::future<void> started = started_promise.get_future();

				{
					ext::reverse_lock rlk(lk);
					LOG_DEBUG("joining thread");
					run_proc(started_promise);
					LOG_DEBUG("run_proc finished");
				}

				m_started = m_joined = false;
				// propagate exceptions
				return started.get();
			}
		}
	}

	void http_server::interrupt()
	{
		bool interrupted = std::exchange(m_interrupted, true);
		// forbid reordering m_interrupted read and write after anything below
		std::atomic_signal_fence(std::memory_order_acq_rel);
		if (not interrupted)
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
		LOG_DEBUG("executing run_proc");
		
		try
		{
			assert(m_sock_queue.empty());
			
			LOG_INFO("configuring {} listeners", m_listener_contexts.size());
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
				m_sock_queue.add_listener(listener.handle());
			}

			started_promise.set_value();
			LOG_DEBUG("running main loop");
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
		LOG_DEBUG("exiting run_proc");
		EXT_UNUSED(got_exception);
		m_running = false;
		do_reset(lk);
	}

	void http_server::run_sockqueue()
	{
		for (;;)
		{
			socket_queue::wait_status status;
			handle_type sock;
			std::error_code errc;
			std::tie(status, sock, errc) = m_sock_queue.take();

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
			
			auto context = reinterpret_cast<processing_context *>(m_sock_queue.ltsud());
			bool newconn = m_sock_queue.lasl() != invalid_socket;
			assert((context != nullptr) xor newconn);

			process_socket(ext::net::socket_uhandle(sock), context, errc);
		}
	}
	
	void http_server::process_socket(ext::net::socket_uhandle usock, processing_context * socket_context, std::error_code socket_errc)
	{
		auto sock = usock.handle();
		bool newconn = socket_context == nullptr;
		
		if (newconn)
			LOG_INFO("got connection(sock={}): peer {} <-> sock {}", sock, peer_endpoint_noexcept(sock), sock_endpoint_noexcept(sock));
		
		// check if socket become ready because of error
		if (socket_errc)
		{
			if (socket_context)
				release_connection(socket_context, socket_errc);
			else
				close_connection(std::move(usock), socket_errc);
			
			return;
		}
		
		if (not socket_context)
		{
			assert(newconn);
			setsock_nonblocking(sock);
			
			socket_context = acquire_context();
			if (not socket_context)
				goto drop_connection;
			
			socket_context->sock = std::move(usock);
			prepare_context(socket_context);
		}
		
	//process_connection:
		// at this point sock guaranteed to be set into context
		usock.release();
		
		// run_socket will do full handling of socket, asyncly if needed:
		// * parse request
		// * process request
		// * write request
		// * place socket back into queue or close it, depending on errors/Close header
		run_socket(socket_context);
		return;

	drop_connection:
		LOG_WARN("dropping connection(sock={}) due to no available processing contexts", sock);
		close_connection(std::move(usock));
		return;
	}

	void http_server::run_socket(processing_context * context)
	{
		auto next_method = std::exchange(context->next_method, nullptr);
		if (not next_method) next_method = &http_server::handle_start;

		if (not m_processing_executor)
			executor_handle_runner(next_method, std::move(context));
		else
		{
			auto fres = m_processing_executor->submit(&http_server::executor_handle_runner, this, next_method, context);
			auto handle = fres.handle();
			auto old = context->executor_state.exchange(handle.release(), std::memory_order_relaxed);
			if (old) old->release();
		}
	}
	
	void http_server::executor_handle_runner(handle_method_type next_method, processing_context * context)
	{
		try
		{
            again: switch (next_method.type())
			{
				default: EXT_UNREACHABLE();

				// explicit nullptr next_method - do nothing
				case handle_method_type::null: return;
				
				case handle_method_type::method:
					context->cur_method = next_method.regular_ptr();
					next_method = (this->*context->cur_method)(std::move(context));
					goto again;

				case handle_method_type::final: break;
				case handle_method_type::async:
				{
					auto ptr = next_method.future();
					if (ptr->is_pending())
						return submit_async_executor_task(std::move(ptr), std::move(next_method), std::move(context));
					else
					{
						auto * old = context->async_task_state.exchange((ptr.addref(), ptr.get()), std::memory_order_relaxed);
						// actually old should always be null, unless we got some exception from line below(calling next_method),
						// and nobody cleared async_task_state in context. RAII unsures that not happens
						assert(old == nullptr); EXT_UNUSED(old);
						//if (old) old->release();
						
						auto_release_atomic_ptr r(context->async_task_state);
						next_method = (this->*next_method.regular_ptr())(context);
						goto again;
					}
				}

				case handle_method_type::wait_socket:
					context->next_method = next_method.regular_ptr();
					context->wait_type = next_method.socket_wait_type();

					if (m_threadid == std::this_thread::get_id())
						wait_connection(context);
					else
					{
						auto task = std::bind(&http_server::wait_connection, this, context);
						submit_task(std::move(task));
					}

					return;
			}
		}
		catch (std::exception & ex)
		{
			context->conn_action = connection_action_type::close;
			next_method = &http_server::handle_finish;
			LOG_ERROR("exception while processing socket = {}: class - {}; what - {}", context->sock.handle(), boost::core::demangle(typeid(ex).name()), ex.what());
		}
		catch (...)
		{
			context->conn_action = connection_action_type::close;
			next_method = &http_server::handle_finish;
			LOG_ERROR("exception while processing socket = {}: unknown exception(...)", context->sock.handle());
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

	bool http_server::pending_ssl_hanshake(handle_type sock)
	{
		char ch;

		int read = ::recv(sock, &ch, 1, MSG_PEEK);
		if (read <= 0) return false;

		// SSL handshake packet starts with character 22(0x16)
		// https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html
		return ch == 0x16;
	}

	auto http_server::peek(processing_context * context, char * data, int len, int & read) const -> handle_method_type
	{
		auto sock = context->sock.handle();
		std::error_code errc;
	#ifdef EXT_ENABLE_OPENSSL
		auto * ssl = context->ssl_ptr.get();
	#endif

	again:
	#ifdef EXT_ENABLE_OPENSSL
		if (ssl)
		{
			SOCK_LOG_TRACE("calling SSL_read");
			read = ::SSL_peek(ssl, data, len);
			if (read > 0) return nullptr;
			errc = socket_ssl_rw_error(read, ssl);
		}
		else
	#endif
		{
			SOCK_LOG_TRACE("calling recv");
			read = ::recv(sock, data, len, MSG_PEEK);
			if (read > 0) return nullptr;
			errc = socket_rw_error(read, last_socket_error());
		}

		if (errc == std::errc::interrupted) goto again;
	#ifdef EXT_ENABLE_OPENSSL
		if (errc == openssl::ssl_errc::want_read)
		{
			SOCK_LOG_DEBUG("SSL_read: got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}
		if (errc == openssl::ssl_errc::want_write)
		{
			SOCK_LOG_DEBUG("SSL_read: got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}
	#endif
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_DEBUG("recv: got would_block, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}

		if (errc != sock_errc::eof)
		{
			SOCK_LOG_WARN("got system error while processing request(read from socket): {}", format_error(errc));
	#ifdef EXT_ENABLE_OPENSSL
			openssl::openssl_clear_errors();
	#endif
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}

		assert(read == 0 and errc == sock_errc::eof);
		return nullptr;
	}

	auto http_server::recv(processing_context * context, char * data, int len, int & read) const -> handle_method_type
	{
		auto sock = context->sock.handle();
		std::error_code errc;
	#ifdef EXT_ENABLE_OPENSSL
		auto * ssl = context->ssl_ptr.get();
	#endif

	again:
	#ifdef EXT_ENABLE_OPENSSL
		if (ssl)
		{
			SOCK_LOG_TRACE("calling SSL_read");
			read = ::SSL_read(ssl, data, len);
			if (read > 0) return nullptr;
			errc = socket_ssl_rw_error(read, ssl);
		}
		else
	#endif
		{
			SOCK_LOG_TRACE("calling recv");
			read = ::recv(sock, data, len, msg_nosignal);
			if (read > 0) return nullptr;
			errc = socket_rw_error(read, last_socket_error());
		}

		if (errc == std::errc::interrupted) goto again;
	#ifdef EXT_ENABLE_OPENSSL
		if (errc == openssl::ssl_errc::want_read)
		{
			SOCK_LOG_DEBUG("SSL_read: got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}
		if (errc == openssl::ssl_errc::want_write)
		{
			SOCK_LOG_DEBUG("SSL_read: got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}
	#endif
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_DEBUG("recv: got would_block, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}

		if (errc != sock_errc::eof)
		{
			SOCK_LOG_WARN("got system error while processing request(read from socket): {}", format_error(errc));
	#ifdef EXT_ENABLE_OPENSSL
			openssl::openssl_clear_errors();
	#endif
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}

		assert(read == 0 and errc == sock_errc::eof);
		return nullptr;
	}

	auto http_server::send(processing_context * context, const char * data, int len, int & written) const -> handle_method_type
	{
		auto sock = context->sock.handle();
		std::error_code errc;
	#ifdef EXT_ENABLE_OPENSSL
		auto * ssl = context->ssl_ptr.get();
	#endif

	again:
	#ifdef EXT_ENABLE_OPENSSL
		if (ssl)
		{
			SOCK_LOG_TRACE("calling SSL_write");
			written = ::SSL_write(ssl, data, len);
			if (written >= 0) return nullptr;
			errc = socket_ssl_rw_error(written, ssl);
		}
		else
	#endif
		{
			SOCK_LOG_TRACE("calling send");
			written = ::send(sock, data, len, msg_nosignal);
			if (written >= 0) return nullptr;
			errc = socket_rw_error(written, last_socket_error());
		}

		if (errc == std::errc::interrupted) goto again;
	#ifdef EXT_ENABLE_OPENSSL
		if (errc == openssl::ssl_errc::want_read)
		{
			SOCK_LOG_DEBUG("SSL_write: got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}
		if (errc == openssl::ssl_errc::want_write)
		{
			SOCK_LOG_DEBUG("SSL_write: got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}
	#endif
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_DEBUG("send: got would_block, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}

		assert(errc == sock_errc::error);
		SOCK_LOG_WARN("got system error while writting response(send to socket): {}", format_error(errc));
	#ifdef EXT_ENABLE_OPENSSL
		openssl::openssl_clear_errors();
	#endif
		context->conn_action = connection_action_type::close;
		return &http_server::handle_cleanup_and_finish;
	}

	auto http_server::recv_and_parse(processing_context * context) const -> handle_method_type
	{
		auto & buffer = context->input_buffer;
		auto & parser = context->parser;
		
		char * first = buffer.data() + context->input_first;
		char * last  = buffer.data() + context->input_last;
		//int len = static_cast<int>(last - first);
		int len = last - first;

		if (first != last) goto parse;
		
		first = buffer.data();
		last  = first + buffer.size();
		if (auto next = recv(context, first, last - first, len))
			return next;
		
		context->input_first = 0;
		context->input_last = len;
		log_read_buffer(context->sock.handle(), first, len);
		
	parse:
		auto read = parser.parse_message(first, len);
		context->input_first += read;
		
		return nullptr;
	}
	
	auto http_server::recv_and_parse(processing_context * context, std::size_t limit) const -> handle_method_type
	{
		auto & buffer = context->input_buffer;
		auto & parser = context->parser;
		
		char * first = buffer.data() + context->input_first;
		char * last  = buffer.data() + context->input_last;
		int len = last - first;

		if (first != last) goto parse;
		
		first = buffer.data();
		last  = first + buffer.size();
		if (auto next = recv(context, first, last - first, len))
			return next;
		
		context->input_first = 0;
		context->input_last = len;
		context->read_count += len;
		
		if (context->read_count >= limit)
		{
			SOCK_LOG_WARN("http request is to long, {} >= {}, closing connection", context->read_count, limit);
			context->response = create_bad_request_response(context->sock.handle(), connection_action_type::close);
			return &http_server::handle_response;
		}
		
		log_read_buffer(context->sock.handle(), first, len);
		
	parse:
		auto read = parser.parse_message(first, len);
		context->input_first += read;
		
		return nullptr;
	}
	
	std::size_t http_server::recvbuf_size(const handle_type sock) const
	{
		constexpr int max_bufsize = 10 * 1024;
		constexpr int min_bufsize =  2 * 1024;
		
		int n = 0;
		socklen_t m = sizeof(m);
		int res = ::getsockopt(sock, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char *>(&n), &m);
		// if OS not reporting SNDBUF - use maximum
		if (res == -1 or n == 0) return max_bufsize;
		
		return std::clamp(n, min_bufsize, max_bufsize);
	}
	
	std::size_t http_server::sendbuf_size(const handle_type sock) const
	{
		constexpr int max_bufsize = 10 * 1024;
		constexpr int min_bufsize =  2 * 1024;
		
		int n = 0;
		socklen_t m = sizeof(m);
		int res = ::getsockopt(sock, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char *>(&n), &m);
		// if OS not reporting SNDBUF - use maximum
		if (res == -1 or n == 0) return max_bufsize;
		
		return std::clamp(n, min_bufsize, max_bufsize);
	}

	auto http_server::handle_start(processing_context * context) -> handle_method_type
	{
		// we should check for EOF, it's not a error at this point. We should just close this socket in this case.
		// sock.in_avail() will use ioctl(..., FIONREAD, &avail) or SSL_pending.
		if (context->input_first != context->input_last)
			goto success;
		
		// it's possible that select/poll notifies socket is readable/writable, but in fact it's not.
		// We should check for error/would_block if socket does not have pending characters
		char ch; int len;
		if (auto next = peek(context, &ch, 1, len))
			return next;

		if (len > 0) goto success;

		// no error and no data -> EOF -> no request, just close it quietly
		return &http_server::handle_end_processing;

	success:
		if (context->ssl_ptr and context->expect_tls)
			return &http_server::handle_ssl_configuration;

		SOCK_LOG_DEBUG("starting processing of a new http request");
		return &http_server::handle_request_headers_parsing;
	}
	
	auto http_server::handle_end_processing(processing_context * context) -> handle_method_type
	{
		if (context->conn_action == connection_action_type::keep_alive)
		{
			SOCK_LOG_TRACE("http request completely processed, connetion keep-alive");
			return &http_server::handle_cleanup_and_finish;
		}
		
#ifdef EXT_ENABLE_OPENSSL
		if (context->ssl_ptr)
			return &http_server::handle_ssl_shutdown;
#endif
		
		// can't close socket here,
		// see close_connection: prints some info, and erases from some maps by socket handle
		return &http_server::handle_cleanup_and_finish;
	}
	
	void http_server::handle_finish(processing_context * context)
	{
		assert(std::this_thread::get_id() == m_threadid);
		assert(context->conn_action != connection_action_type::def);
		
		if (context->conn_action == connection_action_type::keep_alive)
		{
			cleanup_context(context);
			prepare_context(context);
			submit_connection(context);
		}
		else
		{
			shutdown_connection(context);
			release_connection(context);
		}
	}

	auto http_server::handle_ssl_configuration(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		auto sock = context->sock.handle();

		if (pending_ssl_hanshake(sock))
		{
			if (context->expect_tls)
			{
				return &http_server::handle_ssl_start_handshake;
			}
			else
			{
				SOCK_LOG_WARN("peer requested SSL session, but server is not configured to serve SSL on that listener, closing connection");
				context->conn_action = connection_action_type::close;
				return &http_server::handle_cleanup_and_finish;
			}
		}
		else
		{
			if (context->expect_tls)
			{
				SOCK_LOG_WARN("peer does not requested SSL session, but server is configured to serve SSL on that listener, closing connection");
				context->conn_action = connection_action_type::close;
				return &http_server::handle_cleanup_and_finish;
			}
			else
			{
				return &http_server::handle_request_headers_parsing;
			}
		}
	#else
		assert(false);
		std::terminate();
	#endif
	}

	auto http_server::handle_ssl_start_handshake(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		auto & ssl_ptr = context->ssl_ptr;
		assert(ssl_ptr);
		
		auto sockhandle = context->sock.handle();
		auto * ssl = ssl_ptr.get();

		::SSL_set_mode(ssl, ::SSL_get_mode(ssl) | SSL_MODE_AUTO_RETRY);
		int res = ::SSL_set_fd(ssl, sockhandle);
		if (res) return &http_server::handle_ssl_continue_handshake;

		// SSL_set_fd will fail when it will not be able to create some intenal objects, probably because of insufficient memory
		auto sslerr = ::SSL_get_error(ssl, res);
		SOCK_LOG_ERROR("::SSL_set_fd failure: {}", format_error(openssl::openssl_geterror(sslerr)));
		context->conn_action = connection_action_type::close;
		return &http_server::handle_cleanup_and_finish;
	#else
		assert(false);
		std::terminate();
	#endif
	}

	auto http_server::handle_ssl_continue_handshake(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		auto & ssl_ptr = context->ssl_ptr;
		assert(ssl_ptr);

		std::error_code errc;
		int res;

	again:
		SOCK_LOG_TRACE("calling SSL_accept");
		res = ::SSL_accept(ssl_ptr.get());
		if (res > 0)
		{
			SOCK_LOG_INFO("accepted SSL connection");
			return &http_server::handle_ssl_finish_handshake;
		}

		errc = socket_ssl_rw_error(res, ssl_ptr.get());
		if (errc == std::errc::interrupted) goto again;

		if (errc == openssl::ssl_errc::want_read)
		{
			SOCK_LOG_DEBUG("SSL handshake(SSL_accept): got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, &http_server::handle_ssl_continue_handshake);
		}

		if (errc == openssl::ssl_errc::want_write)
		{
			SOCK_LOG_DEBUG("SSL handshake(SSL_accept): got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, &http_server::handle_ssl_continue_handshake);
		}

		// this should not happen
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_DEBUG("SSL handshake(SSL_accept): got EWOUDLBLOCK/EAGAIN, scheduling socket waiting");
			return async_method(socket_queue::both, &http_server::handle_ssl_continue_handshake);
		}

		SOCK_LOG_WARN("SSL handshake(SSL_accept) failure: {}", format_error(errc));
		openssl::openssl_clear_errors();

		context->conn_action = connection_action_type::close;
		return &http_server::handle_cleanup_and_finish;
	#else
		assert(false);
		std::terminate();
	#endif
	}

	auto http_server::handle_ssl_finish_handshake(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		auto & ssl_ptr = context->ssl_ptr;
		assert(ssl_ptr);

		context->expect_tls = false;
		return &http_server::handle_start;
	#else
		assert(false);
		std::terminate();
	#endif
	}
	
	auto http_server::handle_ssl_shutdown(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		// see description of thw phase SSL_shutdown in description of SSL_shutdown function
		// https://www.openssl.org/docs/manmaster/ssl/SSL_shutdown.html
		
		auto * ssl  = context->ssl_ptr.get();
		assert(ssl);
		
		char ch;
		int res;
		long int rc;
		std::error_code errc;
		
		again: switch (context->async_state)
		{
			case 0:
				context->async_state += 1;
				
			case 1: // first shutdown
				SOCK_LOG_TRACE("calling first phase SSL_shutdown");
				res = ::SSL_shutdown(ssl);
				if (res > 0)
				{
					SOCK_LOG_DEBUG("SSL session shutdown on first phase");
					goto success;
				}
				
				if (res == 0) // should attempt second shutdown
				{
					context->async_state += 1;
					goto again;
				}
				
				// res == -1 - error
				errc = socket_ssl_rw_error(res, ssl);
				if (errc == std::errc::interrupted) goto again;
				
				if (errc == openssl::ssl_errc::want_read)
				{
					SOCK_LOG_DEBUG("SSL_shutdown: got WANT_READ, scheduling socket waiting");
					return async_method(socket_queue::readable, &http_server::handle_ssl_continue_handshake);
				}
		
				if (errc == openssl::ssl_errc::want_write)
				{
					SOCK_LOG_DEBUG("SSL_shutdown: got WANT_WRITE, scheduling socket waiting");
					return async_method(socket_queue::writable, &http_server::handle_ssl_continue_handshake);
				}
		
				// this should not happen
				if (errc == sock_errc::would_block)
				{
					SOCK_LOG_DEBUG("SSL_shutdown: got EWOUDLBLOCK/EAGAIN, scheduling socket waiting");
					return async_method(socket_queue::both, &http_server::handle_ssl_continue_handshake);
				}
				
				goto error;
				
			case 2: // second shutdown
				SOCK_LOG_TRACE("calling second phase SSL_shutdown");
				res = ::SSL_shutdown(ssl);
				assert(res != 0); // on second shutdown we are not expecting 0 result
				
				if (res > 0)
				{
					SOCK_LOG_DEBUG("SSL session shutdown on second phase");
					goto success;
				}
				
				// res == -1 - error
				errc = socket_ssl_rw_error(res, ssl);
				if (errc == std::errc::interrupted) goto again;
				
				if (errc == openssl::ssl_errc::want_read)
				{
					SOCK_LOG_DEBUG("SSL_shutdown: got WANT_READ, scheduling socket waiting");
					return async_method(socket_queue::readable, &http_server::handle_ssl_continue_handshake);
				}
		
				if (errc == openssl::ssl_errc::want_write)
				{
					SOCK_LOG_DEBUG("SSL_shutdown: got WANT_WRITE, scheduling socket waiting");
					return async_method(socket_queue::writable, &http_server::handle_ssl_continue_handshake);
				}
		
				// this should not happen
				if (errc == sock_errc::would_block)
				{
					SOCK_LOG_DEBUG("SSL_shutdown: got EWOUDLBLOCK/EAGAIN, scheduling socket waiting");
					return async_method(socket_queue::both, &http_server::handle_ssl_continue_handshake);
				}
				
				// second shutdown failed, this can be a error,
				// or socket was shutdown by other side, lets check it
				rc = ::recv(::SSL_get_fd(ssl), &ch, 1, MSG_PEEK);
				if (rc != 0) goto error; // rc == 0 -> socket closed
		
				// yes, we got FD_CLOSE, not a error
				goto success;
				
			default: EXT_UNREACHABLE();
		}
		
	error:
		SOCK_LOG_WARN("SSL_shutdown failure: {}", format_error(errc));
		context->async_state = 0;
		context->ssl_ptr.reset();
		openssl::openssl_clear_errors();
		context->conn_action = connection_action_type::close;
		return &http_server::handle_cleanup_and_finish;
		
	success:
		context->async_state = 0;
		context->ssl_ptr.reset();
		return &http_server::handle_end_processing;
		
	#else
		assert(false);
		std::terminate();
	#endif
	}

	auto http_server::handle_request_headers_parsing(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & buffer = context->input_buffer;
		auto & response = context->response;
		auto & parser = context->parser;
		auto & config = *context->config;

		SOCK_LOG_DEBUG("parsing http request headers");

		try
		{
			char * first = buffer.data() + context->input_first;
			char * last  = buffer.data() + context->input_last;
			int len = last - first;

			if (first != last) goto parse;

			do
			{
				first = buffer.data();
				last  = first + buffer.size();
				if (auto next = recv(context, first, last - first, len))
					return next;

				context->input_first = 0;
				context->input_last = len;
				context->read_count += len;
				
				if (limit_exceeded(context->read_count, config.maximum_http_headers_size))
				{
					SOCK_LOG_WARN("http request headers are to long, {} >= {}", context->read_count, config.maximum_http_headers_size);
					response = create_bad_request_response(sock, connection_action_type::close);
					return &http_server::handle_response;
				}
								
				log_read_buffer(sock, first, len);
				
			parse:
				auto read = parser.parse_headers(first, len);
				context->input_first += read;

				// It's eof actually, normally it should not happen.
				// Parser should throw exception when sees premature eof, and just eof at start is handled by handle_start.
				// But if there are new line characters(\r or \n, but not any other) then parser would just skip them, like nothing happened.
				// If after that eof came - parser would not throw on parse with len == 0 call.
				// And we actually would got here infinite loop, so we better handle it
				if (len == 0)
				{
					SOCK_LOG_DEBUG("got EOF after some empty lines");
					return &http_server::handle_end_processing;
				}
				
			} while (not parser.headers_parsed());
			
			context->read_count = 0;
			return &http_server::handle_parsed_headers;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got parsing error while processing http request headers: {}", ex.what());
			response = create_bad_request_response(sock, connection_action_type::close);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_request_normal_body_parsing(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & buffer = context->input_buffer;
		auto & response = context->response;
		auto & parser = context->parser;
		auto & config = *context->config;
		
		assert(not (context->filter_ctx and not context->filter_ctx->request_streaming_ctx.filters.empty()));
		SOCK_LOG_DEBUG("parsing http request normal body");

		try
		{
			char * first = buffer.data() + context->input_first;
			char * last  = buffer.data() + context->input_last;
			int len = last - first;

			if (first != last) goto parse;

			do
			{
				first = buffer.data();
				last  = first + buffer.size();
				if (auto next = recv(context, first, last - first, len))
					return next;

				context->input_first = 0;
				context->input_last = len;
				context->read_count += len;
				
				if (limit_exceeded(context->read_count, config.maximum_http_body_size))
				{
					SOCK_LOG_WARN("http request body is to long, {} >= {}", context->read_count, config.maximum_http_body_size);
					response = create_bad_request_response(sock, connection_action_type::close);
					return &http_server::handle_response;
				}
				
				log_read_buffer(sock, first, len);
				
			parse:
				auto read = parser.parse_message(first, len);
				context->input_first += read;
				
			} while (not parser.message_parsed());

			context->read_count = 0;
			return &http_server::handle_parsed_request;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got error while processing normal request body: {}", ex.what());
			response = create_bad_request_response(sock, connection_action_type::close);
			return &http_server::handle_response;
		}
	}
	
	auto http_server::handle_request_filtered_body_parsing(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & buffer = context->input_buffer;
		auto & response = context->response;
		auto & parser = context->parser;
		auto & config = *context->config;
		
		auto & input  = context->request_raw_buffer;
		auto & output = context->request_filtered_buffer;
		
		assert(context->filter_ctx and not context->filter_ctx->request_streaming_ctx.filters.empty());
		auto & params      = context->filter_ctx->request_streaming_ctx.params;
		auto * source_dctx = VECTOR_FRONT(context->filter_ctx->request_streaming_ctx.data_contexts);
		auto * dest_dctx   = VECTOR_BACK(context->filter_ctx->request_streaming_ctx.data_contexts);
				
		SOCK_LOG_DEBUG("parsing http request filtered body");
		
		try
		{
			char * first, * last;
			int len, read;
			
			for (;;)
			{
				switch (context->async_state)
				{
					case 0: // prepare parsing, do some prechecks
						prepare_request_http_body_filtering(context);
						source_dctx = &context->filter_ctx->request_streaming_ctx.data_contexts.front();
						dest_dctx   = &context->filter_ctx->request_streaming_ctx.data_contexts.back();
						
						len = std::clamp(params.default_buffer_size, params.minimum_buffer_size, params.maximum_buffer_size);
						output.resize(std::max(output.capacity(), std::size_t(len)));
						
						first = buffer.data() + context->input_first;
						last  = buffer.data() + context->input_last;
						len   = last - first;
						
						context->async_state = 1 + (first != last);
						context->read_count  = 0;
						continue;
						
					case 1: // read and parse
						first = buffer.data();
						last  = first + buffer.size();
						if (auto next = recv(context, first, last - first, len))
							return next;
						
						context->input_first = 0;
						context->input_last = len;
						context->read_count += len;
						
						if (limit_exceeded(context->read_count, config.maximum_http_body_size))
						{
							context->async_state = 0, context->read_count = 0;
							SOCK_LOG_WARN("http request body is to long, {} >= {}", context->read_count, config.maximum_http_body_size);
							response = create_bad_request_response(sock, connection_action_type::close);
							return &http_server::handle_response;
						}
						
						log_read_buffer(sock, first, len);
						
						context->async_state += 1;
						
					case 2: // parse
						read = parser.parse_message(first, len);
						context->input_first += read;
						
						// If no data was parsed - repeat.
						// This can happen if got few bytes, and they were not body payload,
						// but some service data, like chunk length in chunked encoding.
						if (input.empty() and not parser.message_parsed())
						{
							context->async_state = 1;
							continue;
						}
						
						context->async_state += 1;
						
					case 3: // filter
						source_dctx->data_ptr = input.data();
						source_dctx->written  = input.size();
						source_dctx->capacity = input.size();
						source_dctx->finished = parser.message_parsed();
						
						dest_dctx->data_ptr = output.data();
						dest_dctx->capacity = output.size();
						
						for (;;)
						{
							SOCK_LOG_DEBUG("filtering simple memory request http body with source_dctx = {}/{}/{}, dest_dctx.capacity = {}",
							               source_dctx->written, source_dctx->consumed, source_dctx->finished ? 'f' : 'm', dest_dctx->capacity);
							
							ext::stream_filtering::filter_step(context->filter_ctx->request_streaming_ctx);
							if (dest_dctx->finished or source_dctx->consumed == source_dctx->written) break;
							
							// expand dest buffer if needed
							auto space_avail     = dest_dctx->capacity - dest_dctx->written;
							auto space_threshold = ext::stream_filtering::fullbuffer_threshold(dest_dctx->capacity, params);
							
							if (space_avail <= space_threshold)
							{
								ext::stream_filtering::expand_container(output);
								
								dest_dctx->data_ptr = output.data();
								dest_dctx->capacity = output.size();
							}
							
							// if source data is not finised but we have not so much - break and read more
							// NOTE: source is in fact expanding std::vector<char>, it's capacity will be bigger each time,
							//       but we don't really want that, threshold we are comparing against also grow in this case - bound it by params.default_buffer_size
							auto source_unconsumed = source_dctx->written - source_dctx->consumed;
							auto source_threshold  = ext::stream_filtering::fullbuffer_threshold(std::min(source_dctx->capacity, params.default_buffer_size), params);
							if (not source_dctx->finished and source_unconsumed < source_threshold) break;
						}
						
						// post filtering processing, check if we finished, have trailing data, etc
						
						// check if http body is to big
						if (limit_exceeded(dest_dctx->written, config.maximum_http_body_size))
						{
							context->async_state = 0, context->read_count = 0;
							SOCK_LOG_WARN("http request body is to long after filtering, {} >= {}", dest_dctx->written, config.maximum_http_body_size);
							response = create_bad_request_response(sock, connection_action_type::close);
							return &http_server::handle_response;
						}
					
						if (dest_dctx->finished)
						{
							auto trailing = source_dctx->written - source_dctx->consumed;
							if (not source_dctx->finished or trailing)
							{
								context->async_state = 0, context->read_count = 0;
								
								// Trailing request data after filters are finished. This is a error
								// (for example gzip filter done, but there is some trailing data)
								SOCK_LOG_WARN("http request body have trailing data, after filters are finished, at least {} bytes and {}",
								              trailing, source_dctx->finished ? "read everything from socket" : "have more unread data from socket");
								
								response = create_bad_request_response(sock, connection_action_type::close);
								return &http_server::handle_response;
							}
							
							goto finished;
						}
						
						context->async_state = 1;
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}
			
		finished:
			output.resize(dest_dctx->written);
			copy_into(output, context->request.body);
			
			context->async_state = 0, context->read_count = 0;
			return &http_server::handle_parsed_request;
		}
		catch (std::exception & ex)
		{
			context->async_state = 0, context->read_count = 0;
			SOCK_LOG_WARN("got error while processing filtered request body: {}", ex.what());
			response = create_bad_request_response(sock, connection_action_type::close);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_discarded_request_body_parsing(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & buffer = context->input_buffer;
		auto & parser = context->parser;
		auto & response = context->response;
		auto & config = *context->config;

		SOCK_LOG_DEBUG("discarding http request body");

		try
		{
			char * first = buffer.data() + context->input_first;
			char * last  = buffer.data() + context->input_last;
			int len = last - first;

			if (first != last) goto parse;

			do
			{
				first = buffer.data();
				last  = first + buffer.size();
				if (auto next = recv(context, first, last - first, len))
					return next;

				context->input_first = 0;
				context->input_last = len;
				context->read_count += len;
				
				if (limit_exceeded(context->read_count, config.maximum_discarded_http_body_size))
				{
					SOCK_LOG_WARN("http request is to long, {} >= {}, closing connection", context->read_count, config.maximum_discarded_http_body_size);
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				log_read_buffer(sock, first, len);
				
			parse:
				auto read = parser.parse_message(first, len);
				context->input_first += read;

			} while (not parser.message_parsed());

			context->read_count = 0;
			return &http_server::handle_parsed_request;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got error while discarding http request body: {}", ex.what());
			response = create_bad_request_response(sock, connection_action_type::close);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_request_normal_async_source_body_parsing(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & buffer = context->input_buffer;
		auto & parser = context->parser;
		
		auto uptr = context->body_closer.load(std::memory_order_acquire);
		if (uptr == 0x01) return nullptr;
		
		auto * body = reinterpret_cast<async_http_body_source_impl::closable_http_body_impl *>(uptr);
		auto & data = context->request_raw_buffer;
		auto asked_size = body->m_asked_size;
		
		assert(body->m_state_flags.load(std::memory_order_relaxed) & body->pending_request_mask);
		
		SOCK_LOG_DEBUG("parsing http request body for async source");

		if (body->m_state_flags.load(std::memory_order_relaxed) & body->finished_mask) // finished - return eof
		{
			body->set_value_result(std::nullopt);
			return nullptr;
		}
		
		try
		{
			for (;;)
			{
				char * first = buffer.data() + context->input_first;
				char * last  = buffer.data() + context->input_last;
				int len = last - first;
	
				if (first != last) goto parse;
				
				first = buffer.data();
				last  = first + buffer.size();
				if (auto next = recv(context, first, last - first, len))
					return next;

				context->input_first = 0;
				context->input_last = len;
				log_read_buffer(sock, first, len);
				
			parse:
				auto read = parser.parse_message(first, len);
				context->input_first += read;
				
				if (parser.message_parsed())
					body->m_state_flags.fetch_or(body->finished_mask, std::memory_order_relaxed);
				else if (data.empty()) // explicit empty check for case asked_size == 0 - we need to read something
					continue;
				else if (data.size() < asked_size)
					continue;
				
				if (data.empty()) body->set_value_result(std::nullopt);
				else              body->set_value_result(std::move(data));
				return nullptr;
			};
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got error while processing normal async source request body: {}", ex.what());
			body->set_exception_result(std::current_exception());
			return nullptr;
		}
	}
	
	auto http_server::handle_request_filtered_async_source_body_parsing(processing_context * context) -> handle_method_type
	{
		auto uptr = context->body_closer.load(std::memory_order_acquire);
		if (uptr == 0x01) return nullptr;
		
		auto & parsed_data = context->request_raw_buffer;
		auto & filtered_data = context->request_filtered_buffer;
		
		auto * body = reinterpret_cast<async_http_body_source_impl::closable_http_body_impl *>(uptr);
		auto asked_size = body->m_asked_size;
		
		assert(body->m_filtered);
		assert(context->filter_ctx and not context->filter_ctx->request_streaming_ctx.filters.empty());
		assert(body->m_state_flags.load(std::memory_order_relaxed) & body->pending_request_mask);
		
		SOCK_LOG_DEBUG("parsing and filtering http request body for async source");

		if (body->m_state_flags.load(std::memory_order_relaxed) & body->finished_mask) // finished - return eof
		{
			body->set_value_result(std::nullopt);
			return nullptr;
		}
		
		try
		{
			for (;;)
			{
				auto & source_dctx = context->filter_ctx->request_streaming_ctx.data_contexts.front();
				auto & dest_dctx = context->filter_ctx->request_streaming_ctx.data_contexts.back();
				auto & params = context->filter_ctx->request_streaming_ctx.params;
			
				auto unconsumed = source_dctx.written - source_dctx.consumed;
				auto threshold  = ext::stream_filtering::emptybuffer_threshold(params.default_buffer_size, params);
				
				// if less than 20% and source is not finished - read some
				if (unconsumed < threshold and not source_dctx.finished)
				{
					auto first = parsed_data.begin();
					auto last  = first + source_dctx.consumed;
					parsed_data.erase(first, last);
					
					source_dctx.written -= source_dctx.consumed;
					source_dctx.consumed = 0;
					
					// read and parse data from socket
					do if (auto next = recv_and_parse(context)) return next;
					while (parsed_data.empty() and not context->parser.message_parsed());
					
					// update/prepare source filtering context
					source_dctx.data_ptr = parsed_data.data();
					source_dctx.written = source_dctx.capacity = parsed_data.size();
					source_dctx.finished = context->parser.message_parsed();
				}
				
				dest_dctx.data_ptr = filtered_data.data();
				dest_dctx.capacity = filtered_data.size();
				filter_request_http_body(context);
				
				unconsumed = dest_dctx.written - dest_dctx.consumed;
				threshold  = ext::stream_filtering::emptybuffer_threshold(dest_dctx.capacity, params);
				if (unconsumed < threshold and not dest_dctx.finished) continue;
				
				if (dest_dctx.finished)
					body->m_state_flags.fetch_or(body->finished_mask, std::memory_order_relaxed);
				else if (dest_dctx.written == 0) // explicit empty check for case asked_size == 0 - we need to read something
					continue;
				else if (dest_dctx.written < asked_size)
					continue;
				
				if (dest_dctx.written == 0) 
					body->set_value_result(std::nullopt);
				else 
				{
					filtered_data.resize(dest_dctx.written), dest_dctx.written = 0;
					body->set_value_result(std::move(filtered_data));
				}
				
				return nullptr;
			};
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got error while processing filtered async source request: {}", ex.what());
			body->set_exception_result(std::current_exception());
			return nullptr;
		}
	}
	
	auto http_server::handle_parsed_headers(processing_context * context) -> handle_method_type
	{
		auto & request = context->request;
		auto & parser = context->parser;
		SOCK_LOG_DEBUG("http request headers parsed");

		request.method = parser.http_method();
		request.http_version = parser.http_version();
		static_assert(static_cast<unsigned>(connection_action_type::close) == 1 and static_cast<unsigned>(connection_action_type::keep_alive) == 2);
		context->conn_action = request.conn_action = static_cast<connection_action_type>(1 + static_cast<unsigned>(parser.should_keep_alive()));

		return &http_server::handle_prefilters;
	}

	auto http_server::handle_prefilters(processing_context * context) -> handle_method_type
	{
		try
		{
			for (const auto * filter : context->config->prefilters)
			{
				if (context->response_is_null)
				{
					SOCK_LOG_DEBUG("got null response from prefilter, connection will be closed");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				// if response overridden - return it
				if (context->response_is_final)
					return &http_server::handle_request_header_processing;
				
				filter->prefilter(context->control);
			}
			
			// if already have response - use it
			if (std::holds_alternative<http_response>(context->response))
				return &http_server::handle_request_header_processing;

			return &http_server::handle_find_handler;
		}
		catch (std::exception & ex)
		{
			SOCK_LOG_WARN("pre-filters processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			context->response = create_internal_server_error_response(context->sock.handle(), context->request, &ex);
			return &http_server::handle_request_header_processing;
		}
		catch (...)
		{
			SOCK_LOG_ERROR("pre-filters unknown processing error");
			context->response = create_internal_server_error_response(context->sock.handle(), context->request, nullptr);
			return &http_server::handle_request_header_processing;
		}
	}

	auto http_server::handle_find_handler(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & request = context->request;
		auto & response = context->response;

		try
		{
			SOCK_LOG_DEBUG("searching http request handler");
			context->handler = find_handler(*context);
			SOCK_LOG_INFO("found http handler {} for {} {}", fmt::ptr(context->handler), request.method, request.url);
			return &http_server::handle_request_header_processing;
		}
		catch (std::exception & ex)
		{
			SOCK_LOG_WARN("handler search error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			response = create_internal_server_error_response(sock, request, &ex);
			return &http_server::handle_request_header_processing;
		}
		catch (...)
		{
			SOCK_LOG_WARN("handler search unknown error");
			response = create_internal_server_error_response(sock, request, nullptr);
			return &http_server::handle_request_header_processing;
		}
	}

	auto http_server::handle_request_header_processing(processing_context * context) -> handle_method_type
	{
		auto & request = context->request;

		// We should handle Expect extension, described in RFC7231 section 5.1.1.
		// https://tools.ietf.org/html/rfc7231#section-5.1.1

		// Only HTTP/1.1 should handle it
		if (request.http_version < 11) return &http_server::handle_request_init_body_parsing;

		ext::ctpred::not_equal_to<ext::aci_char_traits> nieq;
		ext::ctpred::    equal_to<ext::aci_char_traits> ieq;
		// only for POST and PUT
		if (nieq(request.method, "POST") and nieq(request.method, "PUT"))
			return &http_server::handle_request_init_body_parsing;

		auto expect = get_header_value(request.headers, "Expect");
		if (expect.empty()) return &http_server::handle_request_init_body_parsing;

		// Expect can only have one value - 100-continue, others are errors
		context->expect_extension = ieq(expect, "100-continue");

		if (not context->expect_extension)
		{
			SOCK_LOG_WARN("Unsupported Expect: {}; returning 417", expect);
			context->response = create_expectation_failed_response(context);
			return &http_server::handle_response;
		}

		SOCK_LOG_DEBUG("Got Expact: 100-continue");

		// already have answer from prefilters
		if (std::holds_alternative<http_response>(context->response))
		{
			return &http_server::handle_response;
		}
		else if (context->handler)
		{
			SOCK_LOG_DEBUG("Returning 100 Continue");
			context->response = create_continue_response(context);
			context->continue_answer = true;
			return &http_server::handle_response;
		}
		else
		{
			// handle_processing will handle null handler
			return &http_server::handle_processing;
		}
	}
	
	auto http_server::handle_request_init_body_parsing(processing_context * context) -> handle_method_type
	{
		auto content_length = get_header_value(context->request.headers, "Content-Length");
		SOCK_LOG_DEBUG("Content-Length http header is \"{}\"", content_length.empty() ? "<not present>" : content_length);
		
		if (not context->handler)
			return &http_server::handle_discarded_request_body_parsing;
		
		const bool filtered = context->filter_ctx and not context->filter_ctx->request_streaming_ctx.filters.empty();
		if (filtered) 
		{
			// redirect http_body parsing into temp buffer
			context->parser.set_body_destination(context->request_raw_buffer);
		}
		
		auto want_type = context->handler->wanted_body_type(context->control);
		switch (want_type)
		{
			case http_body_type::string:
				context->request.body = std::string();
				return not filtered ? &http_server::handle_request_normal_body_parsing 
				                    : &http_server::handle_request_filtered_body_parsing;
			case http_body_type::vector:
				context->request.body = std::vector<char>();
				return not filtered ? &http_server::handle_request_normal_body_parsing 
				                    : &http_server::handle_request_filtered_body_parsing;
			case http_body_type::stream:
				context->request.body = std::make_unique<http_body_streambuf_impl>(this, context);
				return &http_server::handle_parsed_request;
			case http_body_type::async:
				context->request.body = std::make_unique<async_http_body_source_impl>(this, context);
				return &http_server::handle_parsed_request;
			
			case http_body_type::lstream:
				EXT_UNREACHABLE();
			
			case http_body_type::null:
				return &http_server::handle_discarded_request_body_parsing;
				
			default:
				EXT_UNREACHABLE();
		}
	}

	auto http_server::handle_parsed_request(processing_context * context) -> handle_method_type
	{
		auto & request = context->request;

		SOCK_LOG_DEBUG("http request succesfully parsed");
		//static_assert(connection_action_type::close == 1 and connection_action_type::keep_alive == 2);
		//context->conn_action = request.conn_action = static_cast<connection_action_type>(1 + static_cast<unsigned>(parser.should_keep_alive()));

		log_request(request);
		return &http_server::handle_processing;
	}

	auto http_server::handle_processing(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & response = context->response;
		auto & request = context->request;
		auto * handler = context->handler;

		// already have response from filters
		if (std::holds_alternative<http_response>(response))
			return &http_server::handle_response;

		if (handler)
		{
			SOCK_LOG_INFO("invoking http handler", request.method, request.url);
			response = process_request(context);
		}
		else
		{
			SOCK_LOG_INFO("no http handler, returning 404", request.method, request.url);
			response = create_unknown_request_response(sock, request);
		}

		if (not m_running)
		{
			SOCK_LOG_INFO("abandoning http_response processing, server is stopping");
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
		
		return &http_server::handle_processing_result;
	}

	auto http_server::handle_processing_result(processing_context * context) -> handle_method_type
	{
		auto visitor = [this, context](auto & val) -> handle_method_type
		{
			auto & response = context->response;
			using arg_type = std::remove_reference_t<decltype(val)>;

			if constexpr (ext::is_future_type_v<arg_type>)
			{
				if (val.is_ready() or val.is_deferred())
				{
					SOCK_LOG_INFO("async http_handler response ready");
					response = process_ready_response(std::move(val), context->sock.handle(), context->request);
					return &http_server::handle_processing_result;
				}
				else
				{
					SOCK_LOG_INFO("async http_handler response, scheduling async processing");
					return async_method(val.handle(), &http_server::handle_processing_result);
				}
			}
			else if constexpr (std::is_same_v<arg_type, null_response_type>)
			{
				SOCK_LOG_DEBUG("got null response from http_handler, connection will be closed");
				context->response_is_null = true;
				context->conn_action = connection_action_type::close;
				return &http_server::handle_cleanup_and_finish;
			}
			else // http_response
			{
				SOCK_LOG_DEBUG("got response from http_handler");
				return &http_server::handle_postfilters;
			}
		};

		return std::visit(visitor, context->response);
	}

	auto http_server::handle_postfilters(processing_context * context) -> handle_method_type
	{
		try
		{
			// at this moment, context->response should only contain http_response
			assert(std::holds_alternative<http_response>(context->response));
			for (const auto * filter : context->config->postfilters)
			{
				if (context->response_is_null)
				{
					SOCK_LOG_DEBUG("got null response from postfilter, connection will be closed");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				if (context->response_is_final)
					break;
				
				filter->postfilter(context->control);
			}

			return &http_server::handle_response;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("post-filters processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			context->response = create_internal_server_error_response(context->sock.handle(), context->request, &ex);
			return &http_server::handle_response;
		}
		catch (...)
		{
			SOCK_LOG_ERROR("post-filters unknown processing error");
			context->response = create_internal_server_error_response(context->sock.handle(), context->request, nullptr);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_response(processing_context * context) -> handle_method_type
	{
		check_response(context);
		
		if (not context->continue_answer)
			postprocess_response(context);
		
		auto & response = std::get<http_response>(context->response);
		log_response(response);
		context->writer.reset(&response);

		return &http_server::handle_response_headers_writting;
	}

	auto http_server::handle_response_headers_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		auto & writer = context->writer;
		auto & buffer = context->response_raw_buffer;

		SOCK_LOG_DEBUG("writting http response headers");

		try
		{
			if (not m_running)
			{
				SOCK_LOG_INFO("abandoning http_response headers writting, server is stopping");
				context->conn_action = connection_action_type::close;
				return &http_server::handle_cleanup_and_finish;
			}
			
			const char * first, * last;
			int written = buffer.size();
			if (written) goto write;

			do {
				buffer.resize(std::max(buffer.capacity(), std::size_t(2048)));

				written = writer.write_some(buffer.data(), buffer.size());
				buffer.resize(written);

			write:
				first = buffer.data();
				last  = first + buffer.size();
				first += context->written_count;

				if (auto next = send(context, first, last - first, written))
					return next;

				log_write_buffer(sock, first, written);
				context->written_count += written;
				if (first + written < last)
				{
					SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
					return async_method(socket_queue::writable, &http_server::handle_response_headers_writting);
				}

			} while(not writer.finished());

			context->written_count = 0;
			buffer.clear();
			return &http_server::handle_response_headers_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting response headers: {}", ex.what());
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}
	
	auto http_server::handle_response_headers_written(processing_context * context) -> handle_method_type
	{
		SOCK_LOG_DEBUG("http response headers written");
		
		if (context->expect_extension and context->continue_answer)
		{
			SOCK_LOG_DEBUG("continue http request processing after 100 Continue, now parsing body");
			context->first_response_written = true, context->continue_answer = false;
			context->response = null_response; // important! reset 100 Continue response, some code checks it before normal response is generated
			return &http_server::handle_request_init_body_parsing;
		}
		else
		{
			const bool filtered = context->filter_ctx and not context->filter_ctx->response_streaming_ctx.filters.empty();
			
			// at this moment, context->response should only contain http_response
			assert(std::holds_alternative<http_response>(context->response));
			const auto & resp = std::get<http_response>(context->response);
			switch(static_cast<http_body_type>(resp.body.index()))
			{
				case http_body_type::string:
				case http_body_type::vector:
					return not filtered ? &http_server::handle_response_normal_body_writting
					                    : &http_server::handle_response_filtered_body_writting;
					
				case http_body_type::stream:
					return not filtered ? &http_server::handle_response_normal_stream_body_writting
					                    : &http_server::handle_response_filtered_stream_body_writting;
					
				case http_body_type::async:
					return not filtered ? &http_server::handle_response_normal_async_body_writting
					                    : &http_server::handle_response_filtered_async_body_writting;
					
				case http_body_type::lstream:
					return &http_server::handle_response_lstream_body_writting;
					
				case http_body_type::null:
					return &http_server::handle_response_written;
					
				default: EXT_UNREACHABLE();
			}
		}
	}
	
	template <class HttpBody>
	static auto get_data(HttpBody & body) noexcept
	{
		static_assert(std::is_same_v<std::remove_cv_t<HttpBody> ,http_body>);
		using result_type = std::conditional_t<
			std::is_const_v<HttpBody>,
			std::tuple<const char *, const char *>,
			std::tuple<      char *,       char *>>;
		
		assert(std::holds_alternative<std::string>(body) or std::holds_alternative<std::vector<char>>(body));
		return std::visit([](auto & val) -> result_type
		{
			using type = std::decay_t<decltype(val)>;
			if constexpr(std::is_same_v<std::string, type> or std::is_same_v<std::vector<char>, type>)
			{
				auto * first = val.data();
				auto * last  = first + val.size();
				return std::make_tuple(first, last);
			}
			
			EXT_UNREACHABLE();
			
		}, body);
	}
	
	auto http_server::handle_response_normal_body_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		
		SOCK_LOG_DEBUG("writting http response normal body");
		
		try
		{
			if (not m_running)
			{
				SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
				context->conn_action = connection_action_type::close;
				return &http_server::handle_cleanup_and_finish;
			}
			
			const char * first, * last;
			const http_body & body = std::get<http_response>(context->response).body;
			std::tie(first, last) = get_data(body);
			std::size_t size = last - first;
		
			// loop because we can't write more than INT_MAX in one send call, but buffer can be bigger
			do
			{
				auto start = first + context->written_count;
				int len = std::min<std::size_t>(INT_MAX, last - start);
				int written;
	
				if (auto next = send(context, start, len, written))
					return next;
	
				log_write_buffer(sock, start, written);
				context->written_count += written;
				if (written < len)
				{
					SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
					return async_method(socket_queue::writable, &http_server::handle_response_normal_body_writting);
				}
				
			} while (context->written_count < size);

			context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting normal response body: {}", ex.what());
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}
	
	auto http_server::handle_response_filtered_body_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		
		SOCK_LOG_DEBUG("writting http response filtered body");
		
		auto & filtered_buffer = context->response_raw_buffer;
		auto & chunk_prefix = context->chunk_prefix;
		
		const bool filtered = context->filter_ctx and not context->filter_ctx->response_streaming_ctx.filters.empty();
		assert(filtered); EXT_UNUSED(filtered);
		
		auto * source_dctx = VECTOR_FRONT(context->filter_ctx->response_streaming_ctx.data_contexts);
		auto * dest_dctx   = VECTOR_BACK(context->filter_ctx->response_streaming_ctx.data_contexts);
		
		try
		{
			for (;;)
			{
				char * first, * last;
				int written;
				
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				switch (context->async_state)
				{
					case 0: // prepare data for filtering
						assert(chunk_prefix.empty());
						filtered_buffer.resize(std::max(filtered_buffer.capacity(), sendbuf_size(sock)));
						
						prepare_response_http_body_filtering(context);
						std::tie(first, last) = get_data(std::get<http_response>(context->response).body);
						source_dctx = &context->filter_ctx->response_streaming_ctx.data_contexts.front();
						dest_dctx   = &context->filter_ctx->response_streaming_ctx.data_contexts.back();
						
						source_dctx->data_ptr = first;
						source_dctx->written  = last - first;
						source_dctx->capacity = source_dctx->written;
						source_dctx->finished = true;
						
						dest_dctx->data_ptr = filtered_buffer.data();
						dest_dctx->capacity = filtered_buffer.size() - crlf.size();
						
						context->async_state += 1;
						context->written_count = 0;
						
					case 1: // prepare chunk header
						// filter next chunk 
						dest_dctx->written = dest_dctx->consumed = 0;
						filter_response_http_body(context);
						
						first = dest_dctx->data_ptr;
						last  = first + dest_dctx->written;
						// append crlf to chunk data
						last[+0] = crlf[0]; last[+1] = crlf[1];
						
						// now prepare chunk header, print size into buffer with crlf
						chunk_prefix.resize(chunkprefix_size + crlf.size());
						first = ext::unsafe_itoa(dest_dctx->written, chunk_prefix.data(), chunkprefix_size + 1, 16);
						chunk_prefix[chunkprefix_size + 0] = crlf[0];
						chunk_prefix[chunkprefix_size + 1] = crlf[1];
						chunk_prefix.erase(0, first - chunk_prefix.data());
					
						context->written_count = 0;
						context->async_state += 1;
						
					case 2: //write_chunk_prefix:
						first = chunk_prefix.data();
						last  = first + chunk_prefix.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_filtered_body_writting);
						}
						
						chunk_prefix.clear();
						context->async_state += 1;
						context->written_count = 0;
						
					case 3:
						// now send buffer itself after chunk prefix
						first = dest_dctx->data_ptr + context->written_count;
						last  = dest_dctx->data_ptr + dest_dctx->written + crlf.size();
						
						if (auto next = send(context, first, last - first, written))
							return next;
		
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_filtered_body_writting);
						}
						
						// last empty chunk written(still holding \r\n) -> we are finished
						if (dest_dctx->written == 0) goto finished;
						
						context->async_state = 1;
						context->written_count = 0;
						
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}
			
		finished:
			chunk_prefix.clear(), filtered_buffer.clear();
			context->async_state = 0, context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting filtered response body: {}", ex.what());
			context->async_state = 0, context->written_count = 0;
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}

	auto http_server::handle_response_lstream_body_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();
		
		SOCK_LOG_DEBUG("writting http response lstream body");
		
		auto & body = std::get<http_response>(context->response).body;
		auto & stream_ptr = std::get<lstream>(body).stream;
		auto & raw_data = context->response_raw_buffer;
		
		try
		{
			char * first, * last;
			int written;
			
			for (;;)
			{
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				switch (context->async_state)
				{
					case 0: // initial preparing
						raw_data.resize(std::max(raw_data.capacity(), sendbuf_size(sock)));
						
						context->async_state += 1;
						context->written_count = 0;
						
					case 1: // read next chunk
						raw_data.resize(raw_data.capacity());
						written = stream_ptr->sgetn(raw_data.data(), raw_data.size());
						raw_data.resize(written);
						
						if (written == 0) goto finished;
						
						context->written_count = 0;
						context->async_state += 1;
						
					case 2: //write_chunk:
						first = raw_data.data();
						last  = first + raw_data.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
		
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_lstream_body_writting);
						}
						
						context->async_state = 1;
						context->written_count = 0;
						
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}

		finished:
			raw_data.clear();
			context->async_state = 0, context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting lstream body: {}", ex.what());
			context->async_state = 0, context->written_count = 0;
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}
	
	auto http_server::handle_response_normal_stream_body_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();

		SOCK_LOG_DEBUG("writting http response normal stream body");
		assert(not context->filter_ctx or context->filter_ctx->response_streaming_ctx.filters.empty());
		
		auto & body = std::get<http_response>(context->response).body;
		auto & stream_ptr = std::get<std::unique_ptr<std::streambuf>>(body);
		
		auto & raw_data = context->response_raw_buffer;
		auto & chunk_prefix  = context->chunk_prefix;
		
		try
		{
			char * first, * last;
			int written;
			
			for (;;)
			{
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				switch (context->async_state)
				{
					case 0: // initial preparing
						assert(chunk_prefix.empty());
						raw_data.resize(std::max(raw_data.capacity(), sendbuf_size(sock)));
						
						context->async_state += 1;
						context->written_count = 0;
						
					case 1: // read and prepare next chunk
						raw_data.resize(raw_data.capacity());
						written = stream_ptr->sgetn(raw_data.data(), raw_data.size() - crlf.size());
						
						raw_data.resize(written + crlf.size());
						raw_data.data()[written + 0] = crlf[0];
						raw_data.data()[written + 1] = crlf[1];
						
						// now prepare chunk header, print size into buffer with crlf
						chunk_prefix.resize(chunkprefix_size + crlf.size());
						first = ext::unsafe_itoa(written, chunk_prefix.data(), chunkprefix_size + 1, 16);
						chunk_prefix[chunkprefix_size + 0] = crlf[0];
						chunk_prefix[chunkprefix_size + 1] = crlf[1];
						chunk_prefix.erase(0, first - chunk_prefix.data());
					
						context->written_count = 0;
						context->async_state += 1;
						
					case 2: //write_chunk_prefix:
						first = chunk_prefix.data();
						last  = first + chunk_prefix.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_normal_stream_body_writting);
						}
						
						chunk_prefix.clear();
						context->async_state += 1;
						context->written_count = 0;
					
					case 3: //write_chunk:
						// now send buffer itself after chunk prefix
						first = raw_data.data();
						last  = first + raw_data.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
		
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_normal_stream_body_writting);
						}
						
						context->async_state = 1;
						context->written_count = 0;
						
						// last empty chunk written(still holding \r\n) -> we are finished
						if (raw_data.size() <= 2) goto finished;
						
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}

		finished:
			chunk_prefix.clear(), raw_data.clear();
			context->async_state = 0, context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting normal stream body: {}", ex.what());
			context->async_state = 0, context->written_count = 0;
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}
	
	auto http_server::handle_response_filtered_stream_body_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();

		SOCK_LOG_DEBUG("writting http response filtered stream body");
		assert(context->filter_ctx and not context->filter_ctx->response_streaming_ctx.filters.empty());
		
		auto & raw_data        = context->response_raw_buffer;
		auto & filtered_buffer = context->response_filtered_buffer;
		auto & chunk_prefix    = context->chunk_prefix;

		const http_body & body = std::get<http_response>(context->response).body;
		auto & stream_ptr = std::get<std::unique_ptr<std::streambuf>>(body);
		
		auto & filter_params = context->filter_ctx->response_streaming_ctx.params;
		auto * source_dctx = VECTOR_FRONT(context->filter_ctx->response_streaming_ctx.data_contexts);
		auto * dest_dctx   = VECTOR_BACK(context->filter_ctx->response_streaming_ctx.data_contexts);
		
		try
		{
			std::size_t unconsumed, threshold;
			char * first, * last;
			int written;
			
			for (;;)
			{
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				switch (context->async_state)
				{
					case 0: // prepare for filtering
						assert(chunk_prefix.empty());
						filtered_buffer.resize(std::max(filtered_buffer.capacity(), sendbuf_size(sock)));
						raw_data.resize(std::max(filtered_buffer.capacity(), sendbuf_size(sock)));
						
						prepare_response_http_body_filtering(context);
						source_dctx = &context->filter_ctx->response_streaming_ctx.data_contexts.front();
						dest_dctx   = &context->filter_ctx->response_streaming_ctx.data_contexts.back();
						
						source_dctx->data_ptr = raw_data.data();
						source_dctx->capacity = raw_data.size();
						
						dest_dctx->data_ptr = filtered_buffer.data();
						dest_dctx->capacity = filtered_buffer.size() - crlf.size();
						
						context->async_state += 1;
						context->written_count = 0;
					
					case 1: // read and prepare chunk header
						unconsumed = source_dctx->written - source_dctx->consumed;
						threshold  = ext::stream_filtering::fullbuffer_threshold(source_dctx->capacity, filter_params);
						
						// if less than 80% and source is not finished - read some
						if (unconsumed < threshold and not source_dctx->finished)
						{
							first = raw_data.data() + source_dctx->consumed;
							last  = raw_data.data() + source_dctx->written;
							last  = std::move(first, last, raw_data.data());
							
							source_dctx->written -= source_dctx->consumed;
							source_dctx->consumed = 0;
				
							written = stream_ptr->sgetn(raw_data.data() + source_dctx->written, source_dctx->capacity - source_dctx->written);
							// update/prepare source filtering context
							source_dctx->written += written;
							source_dctx->finished = written == 0;
						}
						
						// filter data
						filter_response_http_body(context);
						
						unconsumed = dest_dctx->written - dest_dctx->consumed;
						threshold  = ext::stream_filtering::fullbuffer_threshold(dest_dctx->capacity, filter_params);
						if (unconsumed < threshold and not dest_dctx->finished)
							continue; // read more
						
						first = dest_dctx->data_ptr;
						last  = first + dest_dctx->written;
						// append crlf to chunk data
						// note: dest_dctx->capacity is less than filtered_buffer.size() by crlf.size()
						last[+0] = crlf[0]; last[+1] = crlf[1];
						
						// now prepare chunk header, print size into buffer with crlf
						chunk_prefix.resize(chunkprefix_size + crlf.size());
						first = ext::unsafe_itoa(dest_dctx->written, chunk_prefix.data(), chunkprefix_size + 1, 16);
						chunk_prefix[chunkprefix_size + 0] = crlf[0];
						chunk_prefix[chunkprefix_size + 1] = crlf[1];
						chunk_prefix.erase(0, first - chunk_prefix.data());
					
						context->written_count = 0;
						context->async_state += 1;
						
					case 2: //write_chunk_prefix:
						first = chunk_prefix.data();
						last  = first + chunk_prefix.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_filtered_stream_body_writting);
						}
						
						chunk_prefix.clear();
						context->async_state += 1;
						context->written_count = 0;
					
					case 3: //write_chunk:
						// now send buffer itself after chunk prefix
						first = dest_dctx->data_ptr;
						last  = first + dest_dctx->written + crlf.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
		
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_filtered_stream_body_writting);
						}
						
						context->async_state = 1;
						context->written_count = 0;
						
						// last empty chunk written(still holding \r\n) -> we are finished
						if (std::exchange(dest_dctx->written, 0) == 0) goto finished;
						
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}

		finished:
			chunk_prefix.clear(), raw_data.clear(), filtered_buffer.clear();
			context->async_state = 0, context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting response filtered stream body: {}", ex.what());
			context->async_state = 0, context->written_count = 0;
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}
	
	auto http_server::handle_response_normal_async_body_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();

		SOCK_LOG_DEBUG("writting http response normal async source body");
		
		auto & raw_data = context->response_raw_buffer;
		auto & chunk_prefix = context->chunk_prefix;
		ext::future<async_http_body_source::chunk_type> fresult;
		
		try
		{
			char * first, * last;
			int written, chunk_length;
			
			for (;;)
			{
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				switch (context->async_state)
				{
					case 0:
						if (not raw_data.empty())
						{
							chunk_length = std::min<std::size_t>(INT_MAX - crlf.size(), raw_data.size());
							context->async_state = 2;
							goto prepare_data;
						}
						
						// request new data chunk
						{
							const http_body & body = std::get<http_response>(context->response).body;
							auto & async_source_ptr = std::get<std::unique_ptr<async_http_body_source>>(body);
							
							fresult = async_source_ptr->read_some(std::move(raw_data));
							if (fresult.is_ready() or fresult.is_deferred())
								goto data_ready;
							
							SOCK_LOG_INFO("async source response, scheduling async processing");
							context->async_state += 1;
							return async_method(fresult.handle(), &http_server::handle_response_normal_async_body_writting);
						}
						
					// extract ready future from context
					case 1:
						{
							assert(context->async_task_state.load(std::memory_order_relaxed));
							auto * state = context->async_task_state.exchange(nullptr, std::memory_order_relaxed);
							fresult = ext::future<async_http_body_source::chunk_type>(ext::intrusive_ptr(state, ext::noaddref));
							assert(fresult.is_ready());
						}
						
					// processing ready data chunk
					data_ready:
						context->async_state = 2;
					case 2:
						{
							auto result = fresult.get();
							if (not result)
							{
								raw_data.clear();
								chunk_length = 0;
							}
							else
							{
								raw_data = std::move(*result);
								chunk_length = std::min<std::size_t>(INT_MAX - crlf.size(), raw_data.size());
								if (raw_data.empty()) // no data, write nothing, repeat data request
								{
									context->async_state = 0;
									continue;
								}
							}
						}
						
					prepare_data:
						// now prepare chunk header, print size into buffer with crlf
						chunk_prefix.resize(chunkprefix_size + crlf.size());
						first = ext::unsafe_itoa(chunk_length, chunk_prefix.data(), chunkprefix_size + 1, 16);
						chunk_prefix[chunkprefix_size + 0] = crlf[0];
						chunk_prefix[chunkprefix_size + 1] = crlf[1];
						chunk_prefix.erase(0, first - chunk_prefix.data());
						
						context->async_state += 1;
						context->written_count = 0;
						
					//write_chunk_prefix:
					case 3:
						first = chunk_prefix.data();
						last  = first + chunk_prefix.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_normal_async_body_writting);
						}
						
						context->async_state += 1;
						context->written_count = 0;
						
						// chunk can be more than INT_MAX, but send accepts only int as length,
						// so for huge bodies we must write in parts, crlf in that case happen to be in the middle of the body.
						// store 2 symbols in chunk_prefix buffer temporary, restore them after part of chunk is written
						chunk_length = std::min<std::size_t>(INT_MAX - crlf.size(), raw_data.size());
						// append crlf after chunk, in any case we need to expand by 2 chars
						raw_data.insert(raw_data.end(), crlf.data(), crlf.data() + crlf.size());
						
						first = raw_data.data();
						last  = first + chunk_length;
						chunk_prefix[0] = last[0]; last[0] = crlf[0];
						chunk_prefix[1] = last[1]; last[1] = crlf[1];
						
					//write_chunk:
					case 4:
						// now send buffer itself after chunk prefix
						first = raw_data.data();
						last  = first + std::min<std::size_t>(INT_MAX, raw_data.size()); // already includes crlf.size()
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_normal_async_body_writting);
						}
						
						context->async_state = 0;
						context->written_count = 0;
						
						last[-2] = chunk_prefix[0];
						last[-1] = chunk_prefix[1];
						
						// last empty chunk written(still holding \r\n) -> we are finished
						if (raw_data.size() <= 2) goto finished;
						
						raw_data.erase(raw_data.begin(), raw_data.begin() + written);
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}
			
		finished:
			chunk_prefix.clear(), raw_data.clear();
			context->async_state = 0, context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting response normal async source body: {}", ex.what());
			context->async_state = 0, context->written_count = 0;
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}
	
	auto http_server::handle_response_filtered_async_body_writting(processing_context * context) -> handle_method_type
	{
		auto sock = context->sock.handle();

		SOCK_LOG_DEBUG("writting http response filtered async source body");
		assert(context->filter_ctx and not context->filter_ctx->response_streaming_ctx.filters.empty());
		
		auto & raw_data        = context->response_raw_buffer;
		auto & filtered_buffer = context->response_filtered_buffer;
		auto & chunk_prefix    = context->chunk_prefix;
		ext::future<async_http_body_source::chunk_type> fresult;
		
		auto * source_dctx = VECTOR_FRONT(context->filter_ctx->response_streaming_ctx.data_contexts);
		auto * dest_dctx   = VECTOR_BACK(context->filter_ctx->response_streaming_ctx.data_contexts);
		
		try
		{
			char * first, * last;
			int written;
			
			for (;;)
			{
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					context->conn_action = connection_action_type::close;
					return &http_server::handle_cleanup_and_finish;
				}
				
				switch (context->async_state)
				{
					case 0: // initial preparing
						assert(chunk_prefix.empty());
						filtered_buffer.resize(std::max(filtered_buffer.capacity(), sendbuf_size(sock)));
						raw_data.resize(std::max(filtered_buffer.capacity(), sendbuf_size(sock)));
						
						prepare_response_http_body_filtering(context);
						source_dctx = &context->filter_ctx->response_streaming_ctx.data_contexts.front();
						dest_dctx   = &context->filter_ctx->response_streaming_ctx.data_contexts.back();
						
						//source_dctx->data_ptr = raw_data.data();
						//source_dctx->capacity = raw_data.size();
						
						dest_dctx->data_ptr = filtered_buffer.data();
						dest_dctx->capacity = filtered_buffer.size() - crlf.size();
						
						context->async_state += 1;
						context->written_count = 0;
					
					case 1:
						// if there is some unconsumed data, or source is finished jump to filtering
						if (source_dctx->consumed < source_dctx->written or source_dctx->finished)
						{
							context->async_state = 3;
							goto filter;
						}
						
						// request new data chunk
						{
							const http_body & body  = std::get<http_response>(context->response).body;
							auto & async_source_ptr = std::get<std::unique_ptr<async_http_body_source>>(body);
							
							fresult = async_source_ptr->read_some(std::move(raw_data));
							if (fresult.is_ready() or fresult.is_deferred())
								goto data_ready;
							
							SOCK_LOG_INFO("async source response, scheduling async processing");
							context->async_state = 2;
							return async_method(fresult.handle(), &http_server::handle_response_filtered_async_body_writting);
						}
						
					// extract ready future from context
					case 2:
						{
							assert(context->async_task_state.load(std::memory_order_relaxed));
							auto * state = context->async_task_state.exchange(nullptr, std::memory_order_relaxed);
							fresult = ext::future<async_http_body_source::chunk_type>(ext::intrusive_ptr(state, ext::noaddref));
							assert(fresult.is_ready());
						}
						
					// processing ready data chunk
					data_ready:
						context->async_state = 3;
					case 3:
						// extract and analyze result
						{
							auto result = fresult.get();
							if (not result)
								raw_data.clear(); // actually should be empty already
							else
							{
								raw_data = std::move(*result);
								if (raw_data.empty()) // no data, write nothing, repeat data request
								{
									context->async_state = 1;
									continue;
								}
							}
							
							// update/prepare source filtering context
							source_dctx->data_ptr = raw_data.data();
							source_dctx->capacity = raw_data.size();
							source_dctx->written  = raw_data.size();
							source_dctx->consumed = 0;
							source_dctx->finished = raw_data.empty();
						}
						
					filter: // filter data
						// because of we want to reuse buffer used to request new data chunk from async source,
						// we have no space to store trailing source data, so we need to process it completely
						for (;;)
						{
							filter_response_http_body(context);
							if (dest_dctx->finished)                           break; // we are finished
							if (dest_dctx->written == dest_dctx->capacity)     break; // no place to write
							if (source_dctx->consumed == source_dctx->written) break; // consumed everything
							// otherwise continue
						}
						
						// filters produced no data, gzip can do that for example. request more
						if (dest_dctx->written == 0 and not dest_dctx->finished)
						{
							context->async_state = 1;
							continue;
						}
						
						first = dest_dctx->data_ptr;
						last  = first + dest_dctx->written;
						// append crlf after chunk
						// note: dest_dctx->capacity is less than filtered_buffer.size() by crlf.size()
						last[+0] = crlf[0]; last[+1] = crlf[1];
						
						// now prepare chunk header, print size into buffer with crlf
						chunk_prefix.resize(chunkprefix_size + crlf.size());
						first = ext::unsafe_itoa(dest_dctx->written, chunk_prefix.data(), chunkprefix_size + 1, 16);
						chunk_prefix[chunkprefix_size + 0] = crlf[0];
						chunk_prefix[chunkprefix_size + 1] = crlf[1];
						chunk_prefix.erase(0, first - chunk_prefix.data());
						
						context->async_state += 1;
						context->written_count = 0;
					
					//write_chunk_prefix:
					case 6:
						first = chunk_prefix.data();
						last  = first + chunk_prefix.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_filtered_async_body_writting);
						}
						
						chunk_prefix.clear();
						context->async_state += 1;
						context->written_count = 0;
					
					//write_chunk:
					case 7:
						// now send buffer itself after chunk prefix
						first = dest_dctx->data_ptr;
						last  = first + dest_dctx->written + crlf.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock, first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_DEBUG("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_filtered_async_body_writting);
						}
						
						context->async_state = 1;
						context->written_count = 0;
						
						// last empty chunk written(still holding \r\n) -> we are finished
						if (std::exchange(dest_dctx->written, 0) == 0) goto finished;
						
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}
			
		finished:
			chunk_prefix.clear(), raw_data.clear(), filtered_buffer.clear();
			context->async_state = 0, context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::exception & ex)
		{
			SOCK_LOG_WARN("got writting error while writting response filtered async source body: {}", ex.what());
			context->async_state = 0, context->written_count = 0;
			context->conn_action = connection_action_type::close;
			return &http_server::handle_cleanup_and_finish;
		}
	}
	
	auto http_server::handle_response_written(processing_context * context) -> handle_method_type
	{
		SOCK_LOG_DEBUG("http response written");

		context->final_response_written = true;
		context->response = null_response;
		
		return &http_server::handle_end_processing;
	}
	
	auto http_server::handle_cleanup_and_finish(processing_context * context) -> handle_method_type
	{
		auto state = context->body_closer.exchange(1, std::memory_order_relaxed);
		if (state > 0x01)
		{
			// It is very important to close body closer here.
			// Objects associated with body closer: http_body_streambuf and async_http_body_source; are holding pointer to processing context.
			// Before we return processing_context to pool or free it, we must severe link from those objects to context, so no use of context will be possible.
			// Severing is done by invoking close method of body_closer.
			// 
			// In normal flow request is processed, than response is written.
			// When processing will get here - object associated with body closer will be finished already,
			// and any further attempts to work with it will just return eof, effectively severing object.
			// 
			// Nevertheless in some cases(when http server is stopping or some complex cases http request body stream and response body stream + some bugs)
			// we can get situation when response is written, yet request body is still being read. To prevent it we must close body_closer
			// 
			// Future returned by close, in normal flow will always be immediately ready.
			// In other cases future can take some time to complete, but overall should not block for long(see implementation of async_http_body_source and http_body_streambuf)
			ext::intrusive_ptr state_ptr(reinterpret_cast<http_server::closable_http_body *>(state), ext::noaddref);
			auto closef = state_ptr->close();
			closef.wait();
		}
		
		context->shutdown_socket = true;
		return &http_server::handle_finish;
	}

	auto http_server::allocate_context() -> processing_context *
	{
		return new processing_context;
	}

	void http_server::destroy_context(processing_context * context) noexcept
	{
		delete context;
	}
		
	auto http_server::acquire_context() -> processing_context *
	{
		if (not m_free_contexts.empty())
		{
			auto * ptr = m_free_contexts.back();
			LOG_DEBUG("reused context = {}, {}/{} - {}/{}", fmt::ptr(ptr), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
			m_free_contexts.pop_back();
			return ptr;
		}
		else if (m_processing_contexts.size() >= m_maximum_contexts)
		{
			LOG_DEBUG("no more contexts: {}/{} - {}/{}", m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
			return nullptr;
		}
		else
		{
			processing_context_uptr context(allocate_context(), {this});
			m_processing_contexts.insert(context.get());
			LOG_DEBUG("allocated new context {}, {}/{} - {}/{}", fmt::ptr(context.get()), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
			return context.release();
		}
	}
	
	void http_server::release_context(processing_context * context)
	{
		assert(not context->sock);
		
		if (m_free_contexts.size() < m_minimum_contexts)
		{
			m_free_contexts.push_back(context);
			LOG_DEBUG("put into reused context {}, {}/{} - {}/{}", fmt::ptr(context), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
		}
		else
		{
			m_processing_contexts.erase(context);
			destroy_context(context);
			LOG_DEBUG("freed context {}, {}/{} {}/{}", fmt::ptr(context), m_free_contexts.size(), m_processing_contexts.size(), m_minimum_contexts, m_maximum_contexts);
		}
	}

	void http_server::prepare_context(processing_context * context)
	{
		assert(context->sock);
		context->conn_action = connection_action_type::close;
		context->next_method = nullptr;

		context->handler = nullptr;
		context->read_count = context->written_count = 0;
		context->input_first = context->input_last = 0;
		context->input_buffer.resize(std::max(context->input_buffer.capacity(), recvbuf_size(context->sock.get())));
		
		context->expect_tls = false;
		context->expect_extension = context->continue_answer = false;
		context->first_response_written = context->final_response_written = false;
		context->shutdown_socket = false;
		context->response_is_final = false;
		context->response_is_null = false;

		context->parser.reset(&context->request);
		context->writer.reset(nullptr);		
		
		context->async_state = 0;
		context->response = null_response;

		if (m_config_context->dirty)
		{
			auto handler_sorter = [](const http_server_handler * ptr1, const http_server_handler * ptr2) noexcept { return ptr1->order() < ptr2->order(); };
			auto presorter = [](const http_prefilter * ptr1, const http_prefilter * ptr2) noexcept { return ptr1->preorder() < ptr2->preorder(); };
			auto postsorter = [](const http_postfilter * ptr1, const http_postfilter * ptr2) noexcept { return ptr1->postorder() < ptr2->postorder(); };

			std::stable_sort(m_config_context->handlers.begin(), m_config_context->handlers.end(), handler_sorter);
			std::stable_sort(m_config_context->prefilters.begin(), m_config_context->prefilters.end(), presorter);
			std::stable_sort(m_config_context->postfilters.begin(), m_config_context->postfilters.end(), postsorter);
			
			m_config_context->dirty = false;
		}
		
		context->config = m_config_context;

		#ifdef EXT_ENABLE_OPENSSL
		bool newconn = m_sock_queue.lasl() != invalid_socket;
		if (newconn)
		{
			auto lhandle = m_sock_queue.lasl();
			
			const auto & listener_context = get_listener_context(lhandle);
			if (listener_context.ssl_ctx)
			{
				context->expect_tls = true;
				auto * ssl = ::SSL_new(listener_context.ssl_ctx.get());
				context->ssl_ptr.reset(ssl, ext::noaddref);

				if (not ssl)
				{
					auto err = openssl::last_error(openssl::error_retrieve::peek);
					LOG_ERROR("Failed to create SSL object: {}", format_error(err));
					openssl::openssl_clear_errors();
				}
			}
		}
		#endif
	}
	
	void http_server::cleanup_context(processing_context * context)
	{
		release_atomic_ptr(context->executor_state);
		release_atomic_ptr(context->async_task_state);
		release_atomic_ptr<http_server::closable_http_body>(context->body_closer);
		
		context->next_method = nullptr;
		context->cur_method = nullptr;
		
		context->config = nullptr;
		context->filter_ctx.reset();
		context->prop_map.reset();
				
		context->input_buffer.clear();
		context->chunk_prefix.clear();
		context->request_raw_buffer.clear();
		context->request_filtered_buffer.clear();
		context->response_raw_buffer.clear();
		context->response_filtered_buffer.clear();
		
		clear(context->request);
		context->response = null_response;
	}
	
	void http_server::wait_connection(processing_context * context)
	{
		assert(std::this_thread::get_id() == m_threadid);
		
		auto timeout = context->cur_method == &http_server::handle_ssl_shutdown ? m_close_socket_timeout : m_socket_timeout;
		m_sock_queue.submit(context->sock.handle(), timeout, context->wait_type);
		m_sock_queue.submit_user_data(reinterpret_cast<std::uintptr_t>(context));
	}

	void http_server::submit_connection(processing_context * context)
	{
		assert(std::this_thread::get_id() == m_threadid);

		// while awaiting new request we can be much more liberal on waiting timeout
		bool socket_ready = context->input_first < context->input_last
		#if EXT_ENABLE_OPENSSL
		    // SSL has it's own internal buffer, that can have pending data
		    or (context->ssl_ptr and ::SSL_pending(context->ssl_ptr.get()) > 0)
		#endif
			;
		
		m_sock_queue.submit(context->sock.handle(), m_keep_alive_timeout, socket_queue::readable, socket_ready);
		m_sock_queue.submit_user_data(reinterpret_cast<std::uintptr_t>(context));
	}
	
	void http_server::shutdown_connection(processing_context * context)
	{
		// actually not necessary
		assert(std::this_thread::get_id() == m_threadid);
		
		// If we successfully wrote http reply - be polite, shutdown socket explicitly.
		// If socket have some unread data, and we closed socket, peer can receive ECONNRESET, instead of eof.
		// If some error/exception occured and we got there earlier - just close socket.
		if (context->shutdown_socket)
		{
			auto sock = context->sock.get();
			int res = ::shutdown(sock, shut_rdwr);
			if (res < 0)
				LOG_WARN("shutdown connection(sock={}) failure; error is {}", sock, format_error(last_socket_error_code()));	
		}
	}
	
	void http_server::release_connection(processing_context * context, const std::error_code & sock_err)
	{
		auto sock = std::move(context->sock);
		
		cleanup_context(context);
		release_context(context);
		
		close_connection(std::move(sock), sock_err);
	}

	void http_server::close_connection(ext::net::socket_uhandle sock, const std::error_code & sock_err)
	{
		assert(std::this_thread::get_id() == m_threadid);
				
		if (sock_err == sock_errc::error)
			LOG_WARN("connection failed(sock={}): peer {} <-> sock {}; error is {}", sock.handle(), peer_endpoint_noexcept(sock.handle()), sock_endpoint_noexcept(sock.handle()), format_error(sock_err));
		else
			LOG_INFO("connection closed(sock={}): peer {} <-> sock {}", sock.handle(), peer_endpoint_noexcept(sock.handle()), sock_endpoint_noexcept(sock.handle()));
		
		auto handle = sock.release();
		int res = ext::net::close(handle);
		if (res < 0)
			LOG_WARN("failed to close socket(sock={}); error is {}", handle, format_error(last_socket_error_code()));
	}

	void http_server::postprocess_response(http_response & resp) const
	{
		if (resp.conn_action == connection_action_type::close)
			set_header(resp.headers, "Connection", "close");
		
		assert(not std::holds_alternative<std::unique_ptr<std::streambuf>>(resp.body)
		   and not std::holds_alternative<std::unique_ptr<async_http_body_source>>(resp.body));
		
		auto opt_bodysize = size(resp.body);
		if (opt_bodysize)
			set_header(resp.headers, "Content-Length", std::to_string(*opt_bodysize));
	}
	
	void http_server::postprocess_response(processing_context * context) const
	{
		assert(std::holds_alternative<http_response>(context->response));
		auto & resp = std::get<http_response>(context->response);
		
		if (resp.conn_action == connection_action_type::def)
			resp.conn_action = context->conn_action;
		
		if (resp.conn_action == connection_action_type::close)
			set_header(resp.headers, "Connection", "close");
		
		const bool filtered = context->filter_ctx and not context->filter_ctx->response_streaming_ctx.filters.empty();
		const bool is_lstream = static_cast<http_body_type>(resp.body.index()) == http_body_type::lstream;
		auto opt_bodysize = size(resp.body);
		if (is_lstream or (opt_bodysize and not filtered))
			set_header(resp.headers, "Content-Length", std::to_string(*opt_bodysize));
		else
		{
			append_header_list_value(resp.headers, "Transfer-Encoding", "chunked");
		}
	}
	
	void http_server::check_response(processing_context * context) const
	{
		auto uptr = context->body_closer.load(std::memory_order_relaxed);
		if (uptr <= 0x01) return;
		
		auto * body_closer = reinterpret_cast<http_server::closable_http_body *>(uptr);
		bool finished = body_closer->is_finished();
		if (not finished)
		{
			SOCK_LOG_WARN("warning, writting response, while request http body not fully read and parsed(stream or async source)");
			//context->conn_action = connection_action_type::close;
		}
	}

	auto http_server::process_request(processing_context * context) -> process_result
	{
		auto sock = context->sock.handle();
		auto * handler = context->handler;
		auto & request = context->request;
		
		try
		{
			return handler->process(context->control);
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

	auto http_server::process_ready_response(async_process_result result, const handle_type sock, http_request & request) -> process_result
	{
		auto visitor = [this, sock, &request](auto & fresp) -> process_result
		{
			try
			{
				if (fresp.is_abandoned())
					return create_processing_abondoned_response(sock, request);

				if (fresp.is_cancelled())
					return create_processing_cancelled_response(sock, request);

				return fresp.get();
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
		};

		return std::visit(visitor, result);
	}

	auto http_server::get_listener_context(socket_handle_type listener_handle) const -> const listener_context &
	{
		auto it = m_listener_contexts.find(listener_handle);
		
		if (it == m_listener_contexts.end())
			throw std::runtime_error(fmt::format("Can't find listener context for handle {}", listener_handle)); // actually should not happen
	
		return it->second;
	}

	auto http_server::find_handler(processing_context & context) const -> const http_server_handler *
	{
		for (auto & handler : context.config->handlers)
			if (handler->accept(context.control))
				return handler;

		return nullptr;
	}

	void http_server::log_request(const http_request & request) const
	{
		if (not m_logger) return;

		static_assert(ext::log::Trace > ext::log::Debug);
		auto log_level = std::min(m_request_logging_level, m_request_body_logging_level);

		auto record = m_logger->open_record(log_level, __FILE__, __LINE__);
		if (not record) return;

		auto & stream = record.get_ostream();
		stream << "logging http request:\n";
		write_http_request(stream, request, m_logger->is_enabled_for(m_request_body_logging_level));

		record.push();
	}

	void http_server::log_response(const http_response & response) const
	{
		if (not m_logger) return;

		static_assert(ext::log::Trace > ext::log::Debug);
		auto log_level = std::min(m_request_logging_level, m_request_body_logging_level);

		auto record = m_logger->open_record(log_level, __FILE__, __LINE__);
		if (not record) return;

		auto & stream = record.get_ostream();
		stream << "logging http response:\n";
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
			
			if (not openssl::last_error(openssl::error_retrieve::peek))
			{
				// if no errors in queue, print errc as is
				auto err = ext::format_error(errc);
				// if it's syscall - print also errno
				if (errc == openssl::ssl_errc::syscall)
					err.append(", errno - ").append(ext::format_errno(errno));
				
				return err;
			}

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

	void http_server::log_read_buffer(handle_type sock_handle, const char * buffer, std::size_t size) const
	{
		if (not m_logger) return;

		auto record = m_logger->open_record(m_read_buffer_logging_level, __FILE__, __LINE__);
		if (not record) return;

		auto & stream = record.get_ostream();
		stream << fmt::format("sock={}, read {} bytes, buffer is:\n", sock_handle, size);
		ext::write_hexdump(buffer, buffer + size, stream);

		record.push();
	}

	void http_server::log_write_buffer(handle_type sock_handle, const char * buffer, std::size_t size) const
	{
		if (not m_logger) return;

		auto record = m_logger->open_record(m_write_buffer_logging_level, __FILE__, __LINE__);
		if (not record) return;

		auto & stream = record.get_ostream();
		stream << fmt::format("sock={}, writting {} bytes, buffer is:\n", sock_handle, size);
		ext::write_hexdump(buffer, buffer + size, stream);

		record.push();
	}


	std::pair<double, double> http_server::parse_accept(const http_request & request)
	{
		double text_weight = 0.0, html_weight = 0.0, def_weight = 0.0;
		auto accept_header = get_header_value(request.headers, "Accept");
		if (accept_header.empty())
			return std::make_pair(text_weight, html_weight);

		def_weight  = extract_weight(accept_header, "*",   def_weight);
		def_weight  = extract_weight(accept_header, "*/*", def_weight);
		text_weight = extract_weight(accept_header, "text/plain", def_weight);
		html_weight = extract_weight(accept_header, "text/html",  def_weight);

		return std::make_pair(text_weight, html_weight);
	}

	http_response http_server::create_bad_request_response(const handle_type sock, connection_action_type conn /*= close*/) const
	{
		http_response response;
		response.http_code = 400;
		response.body = response.status = "BAD REQUEST";
		response.conn_action = conn;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_server_busy_response(const handle_type sock, connection_action_type conn /*= close*/) const
	{
		http_response response;
		response.http_code = 503;
		response.status = "Service Unavailable";
		response.body = "Server is busy, too many requests. Repeat later";
		response.conn_action = conn;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_unknown_request_response(const handle_type sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 404;
		response.status = "Not found";
		response.conn_action = request.conn_action;
		response.body = "404 Not found";
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_processing_abondoned_response(const handle_type sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 500;
		response.status = "Internal Server Error";
		response.body = "Request processing abandoned";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_processing_cancelled_response(const handle_type sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 404;
		response.status = "Cancelled";
		response.body = "Request processing cancelled";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_internal_server_error_response(const handle_type sock, const http_request & request, std::exception * ex) const
	{
		http_response response;
		response.http_code = 500;
		response.body = response.status = "Internal Server Error";
		response.conn_action = connection_action_type::close;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_expectation_failed_response(const processing_context * context) const
	{
		http_response response;
		response.http_code = 417;
		response.body = response.status = "Expectation Failed";
		response.conn_action = context->request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_continue_response(const processing_context * context) const
	{
		http_response response;
		response.http_code = 100;
		response.status = "Continue";
		return response;
	}

	auto http_server::current_config() -> config_context &
	{
		if (m_config_context->dirty) return *m_config_context;
		
		m_config_context = std::make_shared<config_context>(*m_config_context);
		m_config_context->dirty = true;
		return *m_config_context;
	}
	
	auto http_server::do_add_listener(listener listener, int backlog, ssl_ctx_iptr ssl_ctx) -> ext::future<void>
	{
		assert(listener.is_socket());
		std::unique_lock lk(m_mutex);
		if (m_started)
		{
			auto task = [this, listener = std::move(listener), backlog, ssl_ctx = std::move(ssl_ctx)]() mutable
			{
				auto addr = listener.sock_endpoint();
				listener_context context;
				context.listener = std::move(listener);
				context.backlog = backlog > 0 ? backlog : m_default_backlog;
				context.ssl_ctx = std::move(ssl_ctx);

				//bool inserted;
				auto [it, inserted] = m_listener_contexts.emplace(listener.handle(), std::move(context));
				if (not inserted)
				{
					auto err_msg = fmt::format("Can't add listener(handle = {}) on {}, already have one", listener.handle(), addr);
					LOG_ERROR("{}", err_msg);
					throw std::runtime_error(err_msg);
				}
				
				auto & l = it->second.listener;
				if (not l.is_listening())
					l.listen(context.backlog);

				LOG_INFO("listening on {}", addr);
				m_sock_queue.add_listener(l.handle());
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
			std::tie(std::ignore, inserted) = m_listener_contexts.emplace(context.listener.handle(), std::move(context));

			if (not inserted)
			{
				auto err_msg = fmt::format("Can't add listener(handle = {}) on {}, already have one", context.listener.handle(), addr);
				LOG_ERROR("{}", err_msg);
				return ext::make_exceptional_future<void>(std::runtime_error(err_msg));
			}

			return ext::make_ready_future();
		}
	}

	void http_server::do_add_handler(std::unique_ptr<const http_server_handler> handler)
	{
		auto & config = current_config();
		
		ext::unconst(handler.get())->set_logger(m_logger);
		config.handlers.push_back(handler.release());
	}

	void http_server::do_add_filter(ext::intrusive_ptr<http_filter_base> filter)
	{
		auto & config = current_config();
		
		filter->set_logger(m_logger);

		if (auto ptr = ext::dynamic_pointer_cast<http_prefilter>(filter))
			config.prefilters.push_back((ptr.addref(), ptr.get()));

		if (auto ptr = ext::dynamic_pointer_cast<http_postfilter>(filter))
			config.postfilters.push_back((ptr.addref(), ptr.get()));
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

	void http_server::add_handler(std::vector<std::string> methods, std::string url, simple_handler_body_function_type function)
	{
		return add_handler(std::make_unique<simple_http_server_handler>(std::move(methods), std::move(url), std::move(function)));
	}

	void http_server::add_handler(std::string url, simple_handler_body_function_type function)
	{
		return add_handler(std::vector<std::string>(), std::move(url), std::move(function));
	}

	void http_server::add_handler(std::string method, std::string url, simple_handler_body_function_type function)
	{
		return add_handler(std::vector<std::string>{std::move(method)}, std::move(url), std::move(function));
	}

	void http_server::add_handler(std::vector<std::string> methods, std::string url, simple_handler_request_function_type function, http_body_type wanted_request_body_type)
	{
		return add_handler(std::make_unique<simple_http_server_handler>(std::move(methods), std::move(url), std::move(function), wanted_request_body_type));
	}

	void http_server::add_handler(std::string url, simple_handler_request_function_type function, http_body_type wanted_request_body_type)
	{
		return add_handler(std::vector<std::string>(), std::move(url), std::move(function), wanted_request_body_type);
	}

	void http_server::add_handler(std::string method, std::string url, simple_handler_request_function_type function, http_body_type wanted_request_body_type)
	{
		return add_handler(std::vector<std::string>{std::move(method)}, std::move(url), std::move(function), wanted_request_body_type);
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
	
	void http_server::set_maximum_http_headers_size(unsigned size)
	{
		submit_task([this, size]
		{
			m_config_context->dirty = true;
			m_config_context->maximum_http_headers_size = size;
		});
	}
	
	auto http_server::get_maximum_http_headers_size() -> unsigned
	{
		return submit_task([this]
		{
			return m_config_context->maximum_http_headers_size;
		}).get();
	}
	
	void http_server::set_maximum_http_body_size(unsigned size)
	{
		submit_task([this, size]
		{
			m_config_context->dirty = true;
			m_config_context->maximum_http_body_size = size;
		});
	}
	
	auto http_server::get_maximum_http_body_size() -> unsigned
	{
		return submit_task([this]
		{
			return m_config_context->maximum_http_body_size;
		}).get();
	}
	
	void http_server::set_maximum_discarded_http_body_size(unsigned size)
	{
		submit_task([this, size]
		{
			m_config_context->dirty = true;
			m_config_context->maximum_discarded_http_body_size = size;
		});
	}
	
	auto http_server::get_maximum_discarded_http_body_size() -> unsigned
	{
		return submit_task([this]
		{
			return m_config_context->maximum_discarded_http_body_size;
		}).get();
	}
	
	http_server::http_server()
	    : m_config_context(std::make_shared<config_context>()) {};
	http_server::~http_server() { destruct(); };
}
