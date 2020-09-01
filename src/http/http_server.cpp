#include <ext/itoa.hpp>
#include <ext/reverse_lock.hpp>
#include <ext/errors.hpp>
#include <ext/functors/ctpred.hpp>
#include <ext/hexdump.hpp>

#include <boost/core/demangle.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/iterator/transform_iterator.hpp>

#include <ext/net/socket_include.hpp>
#include <ext/net/http/http_server.hpp>
#include <ext/net/http/http_server_ext.hpp>
#include <ext/net/http/http_server_logging_helpers.hpp>


namespace ext::net::http
{
	template <class Type>
	inline static void release_atomic_ptr(std::atomic<Type *> & pointer)
	{
		auto old = pointer.exchange(nullptr, std::memory_order_relaxed);
		if (old) ext::intrusive_ptr_release(old);
	}
	
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
			auto it = list.iterator_to(*this);
			list.erase(it);

			owner->submit_handler(lk, std::move(m_method), m_context);

			notify = delayed_count == 0 or --delayed_count == 0;
			running = owner->m_running;
		}

		// notify http_server if needed
		if (running) owner->m_sock_queue.interrupt();
		if (notify)  owner->m_event.notify_one();

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

	void http_server::do_reset(std::unique_lock<std::mutex> & lk)
	{
		assert(lk.owns_lock());
		assert(m_running == false);
		LOG_DEBUG("stopping and cleaning server state");
		
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
		
		std::vector<ext::future<void>> waiting_tasks;
		waiting_tasks.reserve(m_processing_contexts.size());
		
		{ // close(and interrupt) any http_body stream/source
			for (auto * context : m_processing_contexts)
			{
				auto state = context->body_closer.exchange(reinterpret_cast<closable_http_body *>(1), std::memory_order_relaxed);
				if (not state) continue;
			
				ext::intrusive_ptr state_ptr(state, ext::noaddref);
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

		// and delete any processing contexts
		for (auto * context : m_processing_contexts)
			destruct_context(context), delete context;

		m_pending_contexts.clear();
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
				m_started = m_running = true;
				std::atomic_signal_fence(std::memory_order_release);
				m_joined = true;
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
		// TODO: there should be "interrupted" atomic flag, that is set by this method, and checked in join_thread
		//       currently we have a race condition here, when interrupt comes earlier then join_thread sets m_joined = true
		
		// forbid reordering m_joined read after anything below
		std::atomic_signal_fence(std::memory_order_acquire);
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
		LOG_TRACE("executing run_proc");
		
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
				m_sock_queue.add_listener(std::move(listener));
			}

			started_promise.set_value();
			LOG_TRACE("running main loop");
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
		LOG_TRACE("exiting run_proc");
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

			// check if socket become ready because of error
			if (sock.last_error())
			{
				release_context(sock);
				close_connection(std::move(sock));
				continue;
			}

			// set socket operation timeout, while in sock_queue socket have m_keep_alive_timeout
			sock.timeout(m_socket_timeout);

			auto * context = acquire_context(std::move(sock));
			if (context)
			{
				// run_socket will do full handling of socket, asyncly if needed:
				// * parse request
				// * process request
				// * write request
				// * place socket back into queue or close it, depending on errors/Close header
				run_socket(context);
				continue;
			}
			else
			{
				// This is blocking, but normally answer should fit output socket buffer,
				// so in fact blocking should not occur
				auto response = create_server_busy_response(sock);
				postprocess_response(response);
				write_response(sock, response);
				close_connection(std::move(sock));
				continue;
			}
		}
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
						// and nobody cleared async_task_state in context. RAII will fix this
						if (old) old->release();
						
						next_method = (this->*next_method.regular_ptr())(context);
						release_atomic_ptr(context->async_task_state); // TODO: should be done in RAII manner
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

	static bool pending_ssl_hanshake(socket_streambuf & sock)
	{
		auto handle = sock.handle();
		char ch;

		int read = ::recv(handle, &ch, 1, MSG_PEEK);
		if (read <= 0) return false;

		// SSL handshake packet starts with character 22(0x16)
		// https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html
		return ch == 0x16;
	}

	auto http_server::peek(processing_context * context, char * data, int len, int & read) const -> handle_method_type
	{
		auto & sock = context->sock;
		auto handle = sock.handle();
		assert(not sock.throw_errors());
		std::error_code errc;
	#ifdef EXT_ENABLE_OPENSSL
		auto * ssl = sock.ssl_handle();
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
			read = ::recv(handle, data, len, MSG_PEEK);
			if (read > 0) return nullptr;
			errc = socket_rw_error(read, last_socket_error());
		}

		if (errc == std::errc::interrupted) goto again;
	#ifdef EXT_ENABLE_OPENSSL
		if (errc == openssl::ssl_error::want_read)
		{
			SOCK_LOG_TRACE("SSL_read: got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}
		if (errc == openssl::ssl_error::want_write)
		{
			SOCK_LOG_TRACE("SSL_read: got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}
	#endif
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_TRACE("recv: got would_block, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}

		if (errc != sock_errc::eof)
		{
			SOCK_LOG_WARN("got system error while processing request(read from socket): {}", format_error(errc));
	#ifdef EXT_ENABLE_OPENSSL
			openssl::openssl_clear_errors();
	#endif
			//sock.set_last_error(errc);
			context->conn_action = connection_action_type::close;
			return &http_server::handle_finish;
		}

		assert(read == 0 and errc == sock_errc::eof);
		//sock.set_last_error(errc);
		return nullptr;
	}

	auto http_server::recv(processing_context * context, char * data, int len, int & read) const -> handle_method_type
	{
		auto & sock = context->sock;
		auto handle = sock.handle();
		assert(not sock.throw_errors());
		std::error_code errc;
	#ifdef EXT_ENABLE_OPENSSL
		auto * ssl = sock.ssl_handle();
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
			read = ::recv(handle, data, len, 0);
			if (read > 0) return nullptr;
			errc = socket_rw_error(read, last_socket_error());
		}

		if (errc == std::errc::interrupted) goto again;
	#ifdef EXT_ENABLE_OPENSSL
		if (errc == openssl::ssl_error::want_read)
		{
			SOCK_LOG_TRACE("SSL_read: got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}
		if (errc == openssl::ssl_error::want_write)
		{
			SOCK_LOG_TRACE("SSL_read: got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}
	#endif
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_TRACE("recv: got would_block, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}

		if (errc != sock_errc::eof)
		{
			SOCK_LOG_WARN("got system error while processing request(read from socket): {}", format_error(errc));
	#ifdef EXT_ENABLE_OPENSSL
			openssl::openssl_clear_errors();
	#endif
			//sock.set_last_error(errc);
			context->conn_action = connection_action_type::close;
			return &http_server::handle_finish;
		}

		assert(read == 0 and errc == sock_errc::eof);
		//sock.set_last_error(errc);
		return nullptr;
	}

	auto http_server::send(processing_context * context, const char * data, int len, int & written) const -> handle_method_type
	{
		auto & sock = context->sock;
		auto handle = sock.handle();
		assert(not sock.throw_errors());
		std::error_code errc;
	#ifdef EXT_ENABLE_OPENSSL
		auto * ssl = sock.ssl_handle();
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
			written = ::send(handle, data, len, msg_nosignal);
			if (written >= 0) return nullptr;
			errc = socket_rw_error(written, last_socket_error());
		}

		if (errc == std::errc::interrupted) goto again;
	#ifdef EXT_ENABLE_OPENSSL
		if (errc == openssl::ssl_error::want_read)
		{
			SOCK_LOG_TRACE("SSL_write: got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, context->cur_method);
		}
		if (errc == openssl::ssl_error::want_write)
		{
			SOCK_LOG_TRACE("SSL_write: got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}
	#endif
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_TRACE("send: got would_block, scheduling socket waiting");
			return async_method(socket_queue::writable, context->cur_method);
		}

		assert(errc == sock_errc::error);
		SOCK_LOG_WARN("got system error while writting response(send to socket): {}", format_error(errc));
	#ifdef EXT_ENABLE_OPENSSL
		openssl::openssl_clear_errors();
	#endif
		//sock.set_last_error(errc);
		context->conn_action = connection_action_type::close;
		return &http_server::handle_finish;
	}

	std::size_t http_server::sendbuf_size(processing_context * context) const
	{
		constexpr int max_bufsize = 10 * 1024;
		int n = 0;
		socklen_t m = sizeof(m);
		int res = ::getsockopt(context->sock.handle(), SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char *>(&n), &m);
		if (res == -1) return max_bufsize;

		return std::min(max_bufsize, n);
	}

	auto http_server::handle_start(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		// we should check for EOF, it's not a error at this point. We should just close this socket in this case.
		// sock.in_avail() will use ioctl(..., FIONREAD, &avail) or SSL_pending.
		if (not sock.in_avail())
		{
			// it's possible that select/poll notifies socket is readable/writable, but in fact it's not.
			// We should check for error/would_block if socket does not have pending characters
			char ch; int len;
			if (auto next = peek(context, &ch, 1, len))
				return next;

			if (len > 0) goto success;

			// no error and no data -> EOF -> no request, just close it quitly
			return &http_server::handle_finish;
		}

	success:
		if (context->ssl_ptr)
			return &http_server::handle_ssl_configuration;

		SOCK_LOG_TRACE("starting processing of a new http request");
		return &http_server::handle_request_headers_parsing;
	}

	auto http_server::handle_ssl_configuration(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		auto & sock = context->sock;
		assert(not sock.throw_errors());
		auto & ssl_ptr = context->ssl_ptr;

		if (pending_ssl_hanshake(sock))
		{
			if (ssl_ptr)
			{
				return &http_server::handle_ssl_start_handshake;
			}
			else
			{
				SOCK_LOG_WARN("peer requested SSL session, but server is not configured to serve SSL on that listener, closing connection");
				return &http_server::handle_finish;
			}
		}
		else
		{
			if (ssl_ptr)
			{
				SOCK_LOG_WARN("peer does not requested SSL session, but server is configured to serve SSL on that listener, closing connection");
				return &http_server::handle_finish;
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
		auto & sock = context->sock;
		auto & ssl_ptr = context->ssl_ptr;
		assert(not sock.throw_errors() and ssl_ptr);

		sock.ssl_error_retrieve(openssl::error_retrieve::peek);
		auto sockhandle = sock.handle();
		auto * ssl = ssl_ptr.get();

		::SSL_set_mode(ssl, ::SSL_get_mode(ssl) | SSL_MODE_AUTO_RETRY);
		int res = ::SSL_set_fd(ssl, sockhandle);
		if (res) return &http_server::handle_ssl_continue_handshake;

		// SSL_set_fd will fail when it will not be able to create some intenal objects, probably because of insufficient memory
		auto sslerr = ::SSL_get_error(ssl, res);
		SOCK_LOG_ERROR("::SSL_set_fd failure: {}", format_error(openssl::openssl_geterror(sslerr)));
		return &http_server::handle_finish;
	#else
		assert(false);
		std::terminate();
	#endif
	}

	auto http_server::handle_ssl_continue_handshake(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		auto & sock = context->sock;
		auto & ssl_ptr = context->ssl_ptr;
		assert(not sock.throw_errors() and ssl_ptr);

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

		if (errc == openssl::ssl_error::want_read)
		{
			SOCK_LOG_TRACE("SSL handshake: got WANT_READ, scheduling socket waiting");
			return async_method(socket_queue::readable, &http_server::handle_ssl_continue_handshake);
		}

		if (errc == openssl::ssl_error::want_write)
		{
			SOCK_LOG_TRACE("SSL handshake: got WANT_WRITE, scheduling socket waiting");
			return async_method(socket_queue::writable, &http_server::handle_ssl_continue_handshake);
		}

		// this should not happen
		if (errc == sock_errc::would_block)
		{
			SOCK_LOG_TRACE("SSL handshake: got EWOUDLBLOCK/EAGAIN, scheduling socket waiting");
			return async_method(socket_queue::both, &http_server::handle_ssl_continue_handshake);
		}

		SOCK_LOG_WARN("SSL failure: {}", format_error(errc));
		openssl::openssl_clear_errors();

		return &http_server::handle_finish;
	#else
		assert(false);
		std::terminate();
	#endif
	}

	auto http_server::handle_ssl_finish_handshake(processing_context * context) -> handle_method_type
	{
	#ifdef EXT_ENABLE_OPENSSL
		auto & sock = context->sock;
		auto & ssl_ptr = context->ssl_ptr;
		assert(not sock.throw_errors() and ssl_ptr);

		sock.set_ssl(ssl_ptr.release());
		return &http_server::handle_start;
	#else
		assert(false);
		std::terminate();
	#endif
	}

	auto http_server::handle_request_headers_parsing(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		auto & response = context->response;
		auto & parser = context->parser;

		SOCK_LOG_DEBUG("parsing http request headers");

		try
		{
			char * first = sock.gptr();
			char * last  = sock.egptr();
			int len = last - first;

			if (first != last) goto parse;

			do
			{
				if (context->read_count >= context->maximum_headers_size)
				{
					SOCK_LOG_WARN("http request is to long, {} >= {}", context->read_count, context->maximum_headers_size);
					response = create_bad_request_response(sock, connection_action_type::close);
					return &http_server::handle_response;
				}

				std::tie(first, last) = sock.getbuf();
				if (auto next = recv(context, first, last - first, len))
					return next;

				sock.setg(first, first, first + len);
				log_read_buffer(sock.handle(), first, len);
			parse:
				auto read = parser.parse_headers(first, len);
				sock.gbump(static_cast<int>(read));

			} while (not parser.headers_parsed());

			return &http_server::handle_parsed_headers;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got parsing error while processing http request headers: {}", ex.what());
			response = create_bad_request_response(sock, connection_action_type::close);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_request_body_parsing(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		auto & response = context->response;
		auto & parser = context->parser;

		SOCK_LOG_DEBUG("parsing http request body");

		try
		{
			char * first = sock.gptr();
			char * last  = sock.egptr();
			int len = last - first;

			if (first != last) goto parse;

			do
			{
				std::tie(first, last) = sock.getbuf();
				if (auto next = recv(context, first, last - first, len))
					return next;

				sock.setg(first, first, first + len);
				log_read_buffer(sock.handle(), first, len);
			parse:
				auto read = parser.parse_message(first, len);
				sock.gbump(static_cast<int>(read));

			} while (not parser.message_parsed());

			return &http_server::handle_parsed_request;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got parsing error while processing request: {}", ex.what());
			response = create_bad_request_response(sock, connection_action_type::close);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_discarded_request_body_parsing(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		auto & parser = context->parser;
		auto & response = context->response;

		SOCK_LOG_TRACE("discarding http request body");

		try
		{
			char * first = sock.gptr();
			char * last  = sock.egptr();
			int len = last - first;

			if (first != last) goto parse;

			do
			{
				if (context->read_count >= context->maximum_discard_message_size)
				{
					SOCK_LOG_WARN("http request is to long, {} >= {}, closing connection", context->read_count, context->maximum_discard_message_size);
					context->conn_action = connection_action_type::close;
					return &http_server::handle_finish;
				}

				std::tie(first, last) = sock.getbuf();
				if (auto next = recv(context, first, last - first, len))
					return next;

				sock.setg(first, first, first + len);
				log_read_buffer(sock.handle(), first, len);
			parse:
				auto read = parser.parse_message(first, len);
				sock.gbump(static_cast<int>(read));

			} while (not parser.message_parsed());

			return &http_server::handle_parsed_request;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got parsing error while discarding http request body: {}", ex.what());
			response = create_bad_request_response(sock, connection_action_type::close);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_request_async_body_source_parsing(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		auto & parser = context->parser;
		auto * ptr = context->body_closer.load(std::memory_order_acquire);
		assert(ptr);
		
		auto * body = static_cast<async_http_body_source_impl::closable_http_body_impl *>(ptr);
		auto & promise = body->m_read_promise;
		auto & data = body->m_data;
		
		assert(body->m_pending_request.load(std::memory_order_relaxed));
		
		SOCK_LOG_DEBUG("parsing http request body for async source");
		
		try
		{
			for (;;)
			{
				if (parser.message_parsed()) // finished - return eof
				{
					body->m_finished.store(true, std::memory_order_relaxed);
					body->m_pending_request.store(false, std::memory_order_relaxed);
					promise.set_value(std::nullopt);
					return nullptr;
				}
				
				char * first = sock.gptr();
				char * last  = sock.egptr();
				int len = last - first;
	
				if (first != last) goto parse;
				
				std::tie(first, last) = sock.getbuf();
				if (auto next = recv(context, first, last - first, len))
					return next;

				sock.setg(first, first, first + len);
				log_read_buffer(sock.handle(), first, len);
			parse:
				auto read = parser.parse_message(first, len);
				sock.gbump(static_cast<int>(read));
				
				// no data available after parsing - we either finished or need more data from socket
				if (data.empty()) continue;
				
				body->m_pending_request.store(false, std::memory_order_relaxed);
				promise.set_value(std::move(data));
				return nullptr;
			};
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got parsing error while processing request: {}", ex.what());
			promise.set_exception(std::current_exception());
			return nullptr;
		}
	}
	
	auto http_server::handle_parsed_headers(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		auto & request = context->request;
		auto & parser = context->parser;
		SOCK_LOG_DEBUG("http request headers parsed");

		request.method = parser.http_method();
		request.http_version = parser.http_version();
		static_assert(static_cast<unsigned>(connection_action_type::close) == 1 and static_cast<unsigned>(connection_action_type::keep_alive) == 2);
		context->conn_action = request.conn_action = static_cast<connection_action_type>(1 + static_cast<unsigned>(parser.should_keep_alive()));

		return &http_server::handle_prefilters_headers;
	}

	auto http_server::handle_prefilters_headers(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		try
		{
			for (const auto * filter : context->headers_prefilters)
			{
				auto res = filter->prefilter_headers(context->request);
				if (not res) continue;

				context->response = std::move(*res);
				return &http_server::handle_request_header_processing;
			}

			return &http_server::handle_find_handler;
		}
		catch (std::exception & ex)
		{
			SOCK_LOG_WARN("pre-filters processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			context->response = create_internal_server_error_response(context->sock, context->request, &ex);
			return &http_server::handle_request_header_processing;
		}
		catch (...)
		{
			SOCK_LOG_ERROR("pre-filters unknown processing error");
			context->response = create_internal_server_error_response(context->sock, context->request, nullptr);
			return &http_server::handle_request_header_processing;
		}
	}

	auto http_server::handle_find_handler(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		auto & request = context->request;
		auto & response = context->response;

		try
		{
			SOCK_LOG_TRACE("searching http request handler");
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
		auto & sock = context->sock;
		auto & request = context->request;

		/// We should handle Expect extension, described in RFC7231 section 5.1.1.
		/// https://tools.ietf.org/html/rfc7231#section-5.1.1

		/// Only HTTP/1.1 should handle it
		if (request.http_version < 11) return &http_server::handle_request_init_body_parsing;

		ext::ctpred::not_equal_to<ext::aci_char_traits> nieq;
		ext::ctpred::    equal_to<ext::aci_char_traits> ieq;
		/// only for POST and PUT
		if (nieq(request.method, "POST") and nieq(request.method, "PUT"))
			return &http_server::handle_request_init_body_parsing;

		auto expect = get_header_value(request.headers, "Expect");
		if (expect.empty()) return &http_server::handle_request_init_body_parsing;

		/// Expect can only have one value - 100-contine, others are errors
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
		if (not context->handler)
			return &http_server::handle_discarded_request_body_parsing;
		
		auto want_type = context->handler->wanted_body_type();
		switch (want_type)
		{
			case http_body_type::string:
				context->request.body = std::string();
				return &http_server::handle_request_body_parsing;
			case http_body_type::vector:
				context->request.body = std::vector<char>();
				return &http_server::handle_request_body_parsing;
			case http_body_type::stream:
				context->request.body = std::make_unique<http_body_streambuf_impl>(this, context);
				return &http_server::handle_parsed_request;
			case http_body_type::async:
				context->request.body = std::make_unique<async_http_body_source_impl>(this, context);
				return &http_server::handle_parsed_request;
			case http_body_type::null:
				return &http_server::handle_discarded_request_body_parsing;
			default:
				EXT_UNREACHABLE();
		}
	}

	auto http_server::handle_parsed_request(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		auto & request = context->request;

		SOCK_LOG_DEBUG("http request succesfully parsed");
		//static_assert(connection_action_type::close == 1 and connection_action_type::keep_alive == 2);
		//context->conn_action = request.conn_action = static_cast<connection_action_type>(1 + static_cast<unsigned>(parser.should_keep_alive()));

		log_request(request);
		return &http_server::handle_prefilters_full;
	}

	auto http_server::handle_prefilters_full(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;

		try
		{
			for (const auto * filter : context->full_prefilters)
			{
				auto res = filter->prefilter_full(context->request);
				if (not res) continue;

				context->response = std::move(*res);
				return &http_server::handle_processing;
			}

			return &http_server::handle_processing;
		}
		catch (std::exception & ex)
		{
			SOCK_LOG_WARN("pre-filters processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			context->response = create_internal_server_error_response(context->sock, context->request, &ex);
			return &http_server::handle_response;
		}
		catch (...)
		{
			SOCK_LOG_ERROR("pre-filters unknown processing error");
			context->response = create_internal_server_error_response(context->sock, context->request, nullptr);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_processing(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		auto & response = context->response;
		auto & request = context->request;
		auto * handler = context->handler;

		// already have response from filters
		if (std::holds_alternative<http_response>(response))
			return &http_server::handle_response;

		if (handler)
		{
			SOCK_LOG_INFO("invoking http handler", request.method, request.url);
			response = process_request(sock, *handler, request);
		}
		else
		{
			SOCK_LOG_INFO("no http handler, returning 404", request.method, request.url);
			response = create_unknown_request_response(sock, request);
		}

		return &http_server::handle_processing_result;
	}

	auto http_server::handle_processing_result(processing_context * context) -> handle_method_type
	{
		auto visitor = [this, context](auto & val) -> handle_method_type
		{
			auto & sock = context->sock;
			auto & response = context->response;
			using arg_type = std::remove_reference_t<decltype(val)>;

			if constexpr (ext::is_future_type_v<arg_type>)
			{
				if (val.is_ready() or val.is_deferred())
				{
					SOCK_LOG_INFO("async http_handler response ready");
					response = process_ready_response(std::move(val), context->sock, context->request);
					return &http_server::handle_processing_result;
				}
				else
				{
					SOCK_LOG_INFO("async http_handler response, scheduling async processing");
					return async_method(val.handle(), &http_server::handle_processing_result);
				}
			}
			else if constexpr (std::is_same_v<arg_type, std::nullopt_t>)
			{
				SOCK_LOG_TRACE("got nullopt response from http_handler, connection will be closed");
				context->conn_action = connection_action_type::close;
				return &http_server::handle_finish;
			}
			else // http_response
			{
				SOCK_LOG_TRACE("got response from http_handler");
				if (val.conn_action == connection_action_type::def)
					val.conn_action = context->conn_action;
				return &http_server::handle_postfilters;
			}
		};

		return std::visit(visitor, context->response);
	}

	auto http_server::handle_postfilters(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;

		try
		{
			// at this moment, context->response should only contain http_response
			assert(std::holds_alternative<http_response>(context->response));
			auto & resp = std::get<http_response>(context->response);
			for (const auto * filter : context->postfilters)
				filter->postfilter(context->request, resp);

			return &http_server::handle_response;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("post-filters processing error: class - {}, what - {}", boost::core::demangle(typeid(ex).name()), ex.what());
			context->response = create_internal_server_error_response(context->sock, context->request, &ex);
			return &http_server::handle_response;
		}
		catch (...)
		{
			SOCK_LOG_ERROR("post-filters unknown processing error");
			context->response = create_internal_server_error_response(context->sock, context->request, nullptr);
			return &http_server::handle_response;
		}
	}

	auto http_server::handle_response(processing_context * context) -> handle_method_type
	{
		auto & response = std::get<http_response>(context->response);

		if (not context->continue_answer)
			postprocess_response(response);
		log_response(response);

		auto bufsize = sendbuf_size(context);
		context->output_buffer.reserve(bufsize);
		context->writer.reset(&response);

		return &http_server::handle_response_headers_writting;
	}

	auto http_server::handle_response_headers_writting(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		auto & writer = context->writer;
		auto & output_buffer = context->output_buffer;

		SOCK_LOG_TRACE("writting http response headers");

		try
		{
			char * first, * last;
			int written = output_buffer.size();
			if (written) goto write;

			do {
				assert(output_buffer.capacity() > 0);
				output_buffer.resize(output_buffer.capacity());

				written = writer.write_some(output_buffer.data(), output_buffer.size());
				output_buffer.resize(written);

			write:
				first = output_buffer.data();
				last = first + output_buffer.size();
				first += context->written_count;

				if (auto next = send(context, first, last - first, written))
					return next;

				log_write_buffer(sock.handle(), first, written);
				context->written_count += written;
				if (first + written < last)
				{
					SOCK_LOG_TRACE("send: writting less than got, scheduling socket waiting");
					return async_method(socket_queue::writable, &http_server::handle_response_headers_writting);
				}

			} while(not writer.finished());

			context->written_count = 0;
			output_buffer.clear();
			return &http_server::handle_response_headers_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting response headers: {}", ex.what());
			return &http_server::handle_finish;
		}
	}
	
	auto http_server::handle_response_headers_written(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		SOCK_LOG_TRACE("http response headers written");
		
		if (context->expect_extension and context->continue_answer)
		{
			SOCK_LOG_DEBUG("continue http request processing after 100 Continue, now parsing body");
			context->first_response_written = true, context->continue_answer = false;
			context->response = std::nullopt; // important! reset 100 Continue request, some code checks it before normal response is generated
			return &http_server::handle_request_init_body_parsing;
		}
		else
		{
			// at this moment, context->response should only contain http_response
			assert(std::holds_alternative<http_response>(context->response));
			auto & resp = std::get<http_response>(context->response);
			switch(static_cast<http_body_type>(resp.body.index()))
			{
				case http_body_type::string:
				case http_body_type::vector:
					return &http_server::handle_response_simple_body_writting;
				case http_body_type::stream:
					return &http_server::handle_response_stream_body_writting;
				case http_body_type::async:
					return &http_server::handle_response_async_body_writting;
				case http_body_type::null:
					return &http_server::handle_response_written;
					
				default: EXT_UNREACHABLE();
			}
		}
	}
	
	auto http_server::handle_response_simple_body_writting(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		SOCK_LOG_TRACE("writting http response simple body");
		
		try
		{
			const char * first, * last;
			const http_body & body = std::get<http_response>(context->response).body;
			std::tie(first, last) = std::visit([](auto & val) -> std::pair<const char *, const char *>
			{
				using type = std::decay_t<decltype(val)>;
				if constexpr(std::is_same_v<std::string, type> or std::is_same_v<std::vector<char>, type>)
				{
					auto * first = val.data();
					auto * last  = first + val.size();
					return std::make_pair(first, last);
				}
				
				EXT_UNREACHABLE();
				
			}, body);
		
			first += context->written_count;
			int written = last - first;

			if (auto next = send(context, first, last - first, written))
				return next;

			log_write_buffer(sock.handle(), first, written);
			context->written_count += written;
			if (first + written < last)
			{
				SOCK_LOG_TRACE("send: writting less than got, scheduling socket waiting");
				return async_method(socket_queue::writable, &http_server::handle_response_simple_body_writting);
			}

			context->written_count = 0;
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting simple response body: {}", ex.what());
			return &http_server::handle_finish;
		}
	}

	auto http_server::handle_response_stream_body_writting(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		SOCK_LOG_TRACE("writting http response stream body");
		
		auto & output_buffer = context->output_buffer;
		auto & chunk_prefix = context->chunk_prefix;
		const http_body & body = std::get<http_response>(context->response).body;
		auto & stream_ptr = std::get<std::unique_ptr<std::streambuf>>(body);
		constexpr auto chunkprefix_size = sizeof(int) * CHAR_BIT / 4 + (CHAR_BIT % 4 ? 1 : 0); // in hex
		
		try
		{
			char * first, * last;
			int written;
			
			for (;;)
			{
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					return &http_server::handle_finish;
				}
				
				switch (context->async_state)
				{
					case 0: // prepare chunk header
						
						// read next chunk
						assert(chunk_prefix.empty());
						assert(output_buffer.capacity() > 0);
						output_buffer.resize(output_buffer.capacity());
						// 2 for crlf after chunk
						written = stream_ptr->sgetn(output_buffer.data(), output_buffer.size() - 2);
						output_buffer.resize(written + 2);
						output_buffer.data()[written + 0] = '\r';
						output_buffer.data()[written + 1] = '\n';
						
						// now prepare chunk header, print size into buffer with crlf
						chunk_prefix.resize(chunkprefix_size + 2); // +2 for crlf
						first = ext::unsafe_itoa(written, chunk_prefix.data(), chunkprefix_size + 1, 16);
						chunk_prefix[chunkprefix_size + 0] = '\r';
						chunk_prefix[chunkprefix_size + 1] = '\n';
						chunk_prefix.erase(0, first - chunk_prefix.data());
					
						context->written_count = 0;
						context->async_state += 1;
						
					case 1: //write_chunk_prefix:
						first = chunk_prefix.data();
						last  = first + chunk_prefix.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock.handle(), first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_TRACE("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_headers_writting);
						}
						
						chunk_prefix.clear();
						context->async_state += 1;
						context->written_count = 0;
					
					case 2: //write_chunk:
						// now send buffer itself after chunk prefix
						first = output_buffer.data();
						last  = first + output_buffer.size();
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
		
						log_write_buffer(sock.handle(), first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_TRACE("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_headers_writting);
						}
						
						//output_buffer.clear();
						context->async_state = 0;
						context->written_count = 0;
						
						// last empty chunk written(still holding \r\n) -> we are finished
						if (output_buffer.size() <= 2) goto finished;
						
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}

		finished:
			context->async_state = 0;
			context->written_count = 0;
			chunk_prefix.clear();
			output_buffer.clear();
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting stream response body: {}", ex.what());
			return &http_server::handle_finish;
		}
	}
	
	auto http_server::handle_response_async_body_writting(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		assert(not sock.throw_errors());

		SOCK_LOG_TRACE("writting http response async source body");
		
		auto & output_buffer = context->output_buffer;
		auto & chunk_prefix = context->chunk_prefix;
		ext::future<async_http_body_source::chunk_type> fresult;
		
		constexpr auto chunkprefix_size = sizeof(int) * CHAR_BIT / 4 + (CHAR_BIT % 4 ? 1 : 0); // in hex
		constexpr std::string_view crlf = "\r\n";
		
		
		try
		{
			char * first, * last;
			int written;
			
			for (;;)
			{
				if (not m_running)
				{
					SOCK_LOG_INFO("abandoning http_response body writting, server is stopping");
					return &http_server::handle_finish;
				}
				
				switch (context->async_state)
				{
					// request new data chunk
					case 0:
						{
							const http_body & body = std::get<http_response>(context->response).body;
							auto & async_source_ptr = std::get<std::unique_ptr<async_http_body_source>>(body);
							
							fresult = async_source_ptr->read_some(std::move(output_buffer));
							if (fresult.is_ready() or fresult.is_deferred())
								goto data_ready;
							
							SOCK_LOG_INFO("async source respose, scheduling async processing");
							context->async_state += 1;
							return async_method(fresult.handle(), &http_server::handle_response_async_body_writting);
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
								output_buffer.clear();
								written = 0;
							}
							else
							{
								output_buffer = *result;
								written = std::min<std::size_t>(INT_MAX, output_buffer.size());
								if (output_buffer.empty()) // no data, write nothing, repeat data request
								{
									context->async_state = 0;
									continue;
								}
							}
						}
						
						// append crlf after chunk
						output_buffer.insert(output_buffer.end(), crlf.data(), crlf.data() + crlf.size());
						// now prepare chunk header, print size into buffer with crlf
						chunk_prefix.resize(chunkprefix_size + 2); // +2 for crlf
						first = ext::unsafe_itoa(written, chunk_prefix.data(), chunkprefix_size + 1, 16);
						chunk_prefix[chunkprefix_size + 0] = '\r';
						chunk_prefix[chunkprefix_size + 1] = '\n';
						chunk_prefix.erase(0, first - chunk_prefix.data());
						
					//write_chunk_prefix:
					case 3:
						first = chunk_prefix.data();
						last  = first + std::min<std::size_t>(INT_MAX, chunk_prefix.size());
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock.handle(), first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_TRACE("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_headers_writting);
						}
						
						chunk_prefix.clear();
						context->async_state += 1;
						context->written_count = 0;
					
					//write_chunk:
					case 4:
						// now send buffer itself after chunk prefix
						first = output_buffer.data();
						last  = first + std::min<std::size_t>(INT_MAX, output_buffer.size());
						first += context->written_count;
						
						if (auto next = send(context, first, last - first, written))
							return next;
						
						log_write_buffer(sock.handle(), first, written);
						context->written_count += written;
						if (first + written < last)
						{
							SOCK_LOG_TRACE("send: writting less than got, scheduling socket waiting");
							return async_method(socket_queue::writable, &http_server::handle_response_headers_writting);
						}
						
						//output_buffer.clear();
						context->async_state = 0;
						context->written_count = 0;
						
						// last empty chunk written(still holding \r\n) -> we are finished
						if (output_buffer.size() <= 2) goto finished;
						
						continue;
						
					default: EXT_UNREACHABLE();
				}
			}
			
		finished:
			context->async_state = 0;
			context->written_count = 0;
			chunk_prefix.clear();
			output_buffer.clear();
			return &http_server::handle_response_written;
		}
		catch (std::runtime_error & ex)
		{
			SOCK_LOG_WARN("got writting error while writting stream response body: {}", ex.what());
			return &http_server::handle_finish;
		}
	}
	
	auto http_server::handle_response_written(processing_context * context) -> handle_method_type
	{
		auto & sock = context->sock;
		SOCK_LOG_TRACE("http response written");

		context->final_response_written = true;
		context->response = std::nullopt;
		SOCK_LOG_DEBUG("http request completely processed");
		return &http_server::handle_finish;
	}

	void http_server::handle_finish(processing_context * context)
	{
		assert(std::this_thread::get_id() == m_threadid);
		if (context->conn_action == connection_action_type::close)
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
		release_atomic_ptr(context->executor_state);
		release_atomic_ptr(context->async_task_state);
		release_atomic_ptr(context->body_closer);

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
		context->conn_action = connection_action_type::close;
		context->next_method = nullptr;

		context->handler = nullptr;
		context->read_count = context->written_count = 0;
		context->expect_extension = context->continue_answer = false;
		context->first_response_written = context->final_response_written = false;

		context->parser.reset(&context->request);
		context->writer.reset(nullptr);
		
		context->async_state = 0;
		context->chunk_prefix.clear();
		context->output_buffer.clear();

		context->response = std::nullopt;
		// parser.reset already cleans request

		if (m_state_ver != context->state_ver)
		{
			context->state_ver = m_state_ver;
			context->maximum_headers_size = m_maximum_headers_size;
			context->maximum_discard_message_size = m_maximum_discard_message_size;

			using boost::make_transform_iterator;
			auto get = [](const auto & sptr) { return sptr.get(); };
			auto handler_sorter = [](const http_server_handler * ptr1, const http_server_handler * ptr2) noexcept { return ptr1->order() < ptr2->order(); };
			auto headers_presorter = [](const http_headers_prefilter * ptr1, const http_headers_prefilter * ptr2) noexcept { return ptr1->preorder_headers() < ptr2->preorder_headers(); };
			auto full_presorter = [](const http_full_prefilter * ptr1, const http_full_prefilter * ptr2) noexcept { return ptr1->preorder_full() < ptr2->preorder_full(); };
			auto postsorter = [](const http_post_filter * ptr1, const http_post_filter * ptr2) noexcept { return ptr1->postorder() < ptr2->postorder(); };

			context->handlers.assign(make_transform_iterator(m_handlers.begin(), get), make_transform_iterator(m_handlers.end(), get));
			context->headers_prefilters.assign(make_transform_iterator(m_headers_prefilters.begin(), get), make_transform_iterator(m_headers_prefilters.end(), get));
			context->full_prefilters.assign(make_transform_iterator(m_full_prefilters.begin(), get), make_transform_iterator(m_full_prefilters.end(), get));
			context->postfilters.assign(make_transform_iterator(m_postfilters.begin(), get), make_transform_iterator(m_postfilters.end(), get));

			std::stable_sort(context->handlers.begin(), context->handlers.end(), handler_sorter);
			std::stable_sort(context->headers_prefilters.begin(), context->headers_prefilters.end(), headers_presorter);
			std::stable_sort(context->full_prefilters.begin(), context->full_prefilters.end(), full_presorter);
			std::stable_sort(context->postfilters.begin(), context->postfilters.end(), postsorter);
			std::reverse(context->postfilters.begin(), context->postfilters.end());
		}

		#ifdef EXT_ENABLE_OPENSSL
		if (newconn)
		{
			const auto & listener_context = get_listener_context(context->sock);
			if (listener_context.ssl_ctx)
			{
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

	void http_server::construct_context(processing_context * context) {}
	void http_server::destruct_context(processing_context * context) {}

	auto http_server::acquire_context(socket_streambuf sock) -> processing_context *
	{
		auto it = m_pending_contexts.find(sock.handle());
		if (it != m_pending_contexts.end())
		{
			auto * context = it->second;
			context->sock = std::move(sock);
			m_pending_contexts.erase(it);
			return context;
		}
		else
		{
			bool inserted;
			std::tie(std::ignore, inserted) = m_sock_handles.insert(sock.handle());

			if (inserted)
			{
				sock.throw_errors(false);
				LOG_INFO("got connection(sock={}): peer {} <-> sock {}", sock.handle(), sock.peer_endpoint_noexcept(), sock.sock_endpoint_noexcept());
			}

			auto * context = acquire_context();
			if (context) prepare_context(context, std::move(sock), inserted);
			return context;
		}
	}

	void http_server::release_context(socket_streambuf & sock)
	{
		auto it = m_pending_contexts.find(sock.handle());
		if (it == m_pending_contexts.end()) return;

		auto * context = it->second;
		m_pending_contexts.erase(it);
		return release_context(context);
	}

	void http_server::wait_connection(processing_context * context)
	{
		assert(std::this_thread::get_id() == m_threadid);

		m_pending_contexts.emplace(context->sock.handle(), context);
		m_sock_queue.submit(std::move(context->sock), context->wait_type);
	}

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

	bool http_server::write_response(socket_streambuf & sock, const http_response & resp) const
	{
		try
		{
			sock.throw_errors(true);
			write_http_response(sock, resp, true);
			sock.pubsync();
			sock.throw_errors(false);

			assert(sock.is_valid());
			return resp.conn_action == connection_action_type::keep_alive;
		}
		catch (std::system_error & ex)
		{
			assert(ex.code() == sock.last_error());
			LOG_WARN("response sending failure: {}", format_error(sock.last_error()));
			sock.throw_errors(false);
			return false;
		}
	}

	void http_server::postprocess_response(http_response & resp) const
	{
		if (resp.conn_action == connection_action_type::close)
			set_header(resp.headers, "Connection", "close");

		auto opt_bodysize = size(resp.body);
		if (opt_bodysize)
			set_header(resp.headers, "Content-Length", std::to_string(*opt_bodysize));
		else
		{
			assert(std::holds_alternative<std::unique_ptr<std::streambuf>>(resp.body)
			    or std::holds_alternative<std::unique_ptr<async_http_body_source>>(resp.body));
			set_header(resp.headers, "Transfer-Encoding", "chunked");
		}
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

	auto http_server::process_ready_response(async_process_result result, socket_streambuf & sock, http_request & request) -> process_result
	{
		auto visitor = [this, &sock, &request](auto & fresp) -> process_result
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

	auto http_server::get_listener_context(const socket_streambuf & sock) const -> const listener_context &
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addrptr = reinterpret_cast<sockaddr *>(&addrstore);
		sock.getsockname(addrptr, &addrlen);
		
		auto addr = sock_addr(addrptr);
		auto it = m_listener_contexts.find(addr);
		if (it == m_listener_contexts.end())
		{
			if (addrptr->sa_family == AF_INET)
			{   // IP4
				addr = "0.0.0.0";
				addr += ":";
				ext::itoa_buffer<unsigned short> buffer;
				addr += ext::itoa(sock_port_noexcept(addrptr), buffer);
				it = m_listener_contexts.find(addr);
			}
			else if (addrptr->sa_family == AF_INET6)
			{   // IP6
				addr = "[::]";
				addr += ":";
				ext::itoa_buffer<unsigned short> buffer;
				addr += ext::itoa(sock_port_noexcept(addrptr), buffer);
				it = m_listener_contexts.find(addr);
			}
		}

		if (it == m_listener_contexts.end())
			throw std::runtime_error(fmt::format("can't find listener context for socket {}", sock.handle()));

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
		stream << "logging http request:\n";
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

		auto record = m_logger->open_record(m_read_buffer_logging_level, __FILE__, __LINE__);
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

	http_response http_server::create_bad_request_response(const socket_streambuf & sock, connection_action_type conn /*= close*/) const
	{
		http_response response;
		response.http_code = 400;
		response.body = response.status = "BAD REQUEST";
		response.conn_action = conn;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_server_busy_response(const socket_streambuf & sock, connection_action_type conn /*= close*/) const
	{
		http_response response;
		response.http_code = 503;
		response.status = "Service Unavailable";
		response.body = "Server is busy, too many requests. Repeat later";
		response.conn_action = conn;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}

	http_response http_server::create_unknown_request_response(const socket_streambuf & sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 404;
		response.status = "Not found";
		response.conn_action = request.conn_action;
		response.body = "404 Not found";
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_processing_abondoned_response(const socket_streambuf & sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 500;
		response.status = "Internal Server Error";
		response.body = "Request processing abandoned";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_processing_cancelled_response(const socket_streambuf & sock, const http_request & request) const
	{
		http_response response;
		response.http_code = 404;
		response.status = "Cancelled";
		response.body = "Request processing cancelled";
		response.conn_action = request.conn_action;
		set_header(response.headers, "Content-Type", "text/plain");

		return response;
	}
	
	http_response http_server::create_internal_server_error_response(const socket_streambuf & sock, const http_request & request, std::exception * ex) const
	{
		http_response response;
		response.http_code = 500;
		response.body = response.status = "Internal Server Error";
		response.conn_action = request.conn_action;
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
		ext::unconst(handler.get())->set_logger(m_logger);
		m_handlers.push_back(std::move(handler));
		m_state_ver += 1;
	}

	void http_server::do_add_filter(ext::intrusive_ptr<http_filter_base> filter)
	{
		filter->set_logger(m_logger);

		if (auto ptr = ext::dynamic_pointer_cast<http_headers_prefilter>(filter))
			m_headers_prefilters.push_back(std::move(ptr));

		if (auto ptr = ext::dynamic_pointer_cast<http_full_prefilter>(filter))
			m_full_prefilters.push_back(std::move(ptr));

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
