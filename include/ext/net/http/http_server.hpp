#pragma once
#include <string>
#include <vector>
#include <functional>
#include <iterator>

#include <thread>
#include <mutex>
#include <condition_variable>

#include <boost/container/flat_set.hpp>
#include <boost/container/flat_map.hpp>

#include <ext/config.hpp>
#include <ext/future.hpp>
#include <ext/thread_pool.hpp>
#include <ext/intrusive_ptr.hpp>
#include <ext/library_logger/logger.hpp>

#include <ext/net/socket_stream.hpp>
#include <ext/net/socket_queue.hpp>
#include <ext/net/openssl.hpp>

#include <ext/net/http_parser.hpp>
#include <ext/net/http/http_types.hpp>
#include <ext/net/http/http_server_handler.hpp>
#include <ext/net/http/http_server_filter.hpp>


namespace ext::net::http
{
	/// Simple embedded http server.
	/// Listens for incoming connections on given listeners sockets,
	/// parses http requests, calls registered handler that accepts that request
	///
	/// supports:
	/// * SSL
	/// * http_handlers: sync and async(result is returned via ext::future)
	/// * http_filters
	/// * thread_pool executor
	///
	/// have 2 working modes(those should not be mixed):
	///  * work on current thread(join_thread/interrupt), useful when you want start simple http_server on main thread
	///  * work on internal background thread(start/stop), useful when you do not want block main thread in http_server
	///
	/// NOTE: by default there no preinstalled filters or handlers
	class http_server
	{
		using self_type = http_server;

	public:
		using handle_type   = socket_queue::handle_type;
		using duration_type = socket_queue::duration_type;
		using time_point    = socket_queue::time_point;
		using function_type = simple_http_server_handler::function_type;

		using process_result  = http_server_handler::result_type;
		using async_process_result = ext::future<http_response>;

#ifdef EXT_ENABLE_OPENSSL
		using ssl_ctx_iptr = ext::net::openssl::ssl_ctx_iptr;
#else
		using ssl_ctx_iptr = nullptr_t;
#endif

		// Internally sockets(both regular and listeners) are handled by ext::net::socket_queue, this class is not thread safe
		// (system calls select/poll used by ext::net::socket_queue do not affected by any pthread related functions).
		// So we have background thread(internal or joined) running ext::net::socket_queue, whenever some action is performed via public method
		// it's submitted into internal task queue -> socket_queue interrupted and all pending queued actions are executed on background thread.
		// See m_sock_queue, m_tasks, m_delayed
		//
		// http_request/socket processing:
		//  When there is ready socket in socket_queue - it's taken, http_request is read, then action handler is searched and invoked,
		//  http_response is written back, socket is placed back into the queue or closed.
		//
		//  This whole http processing can be done on executor or, if unset, in background thread.
		//  http action handlers can be async - return ext::future<http_response>, sync - return ready http_response
		//
		//  Currently http request and response are synchronously processed in executor or background thread -
		//  while whole http request will not be read, action handler invoked, http response written back - socket will not be placed back into queue,
		//  and background thread will be busy working with current request/socket, unless processing executor is set.
		//
		//  In case of async special continuation is attached to returned future, it submits special task when http_result future become ready.
		//  This task continues processing of this http request, writes back response, etc(see m_delayed)
		//
		//  There also pre/post http filters, currently those can't be async, but maybe changed in future.
		//  Those can be used for some common functionality: zlib processing, authentication, CORS, other.
		//
		// processing_context:
		//  When http request is processed - processing context is allocated for it, it holds registered filters, handlers and some helper members.
		//  Some minimal numbers of contexts are cached and only reinitialized if needed, if there no cached contexts are available - one is allocated.
		//  When maximum number exceeds - server busy is returned as http answer.
		//
		//  http filters, handlers can added when http server already started. What if we already processing some request and handler is added?
		//  When processing starts context holds snapshot of currently registered handlers, filters and only they are used. It also handles multithreaded issues.
		//  state_ver holds version: whenever filters, handlers changed -> version incremented, processing context snapshot only reinitializes when state_ver differs.
		//
		// handle_* group:
		//  http request is handled by handle_* method group. All methods can be overridden, also to allow more customization, each method returns what must be done next:
		//   handle_request -> handle_prefilters -> .... -> handle_finish
		//
		// TODO: http request and response should be read/written in non blocking mode
		//

	protected:
		using hook_type = boost::intrusive::list_base_hook<
			boost::intrusive::link_mode<boost::intrusive::link_mode_type::normal_link>
		>;

		class task_base; // inherits hook_type
		template <class Functor, class ResultType>
		class task_impl; // implements task_base
		class delayed_async_executor_task_continuation;

		class processing_executor;
		template <class ExecutorPtr>
		class processing_executor_impl;

	protected:
		using list_option = boost::intrusive::base_hook<hook_type>;
		using task_list = boost::intrusive::list<task_base, list_option, boost::intrusive::constant_time_size<false>>;
		using delayed_async_executor_task_continuation_list = boost::intrusive::list<delayed_async_executor_task_continuation, list_option, boost::intrusive::constant_time_size<false>>;		

	protected:
		/// http request parsing result
		enum http_parse_result : unsigned
		{
			success,
			socket_error,
			parse_error,
		};

		/// holds some listener context configuration
		struct listener_context
		{
			unsigned backlog;
			ssl_ctx_iptr ssl_ctx;
			ext::net::listener listener; // valid until it placed into sock_queue
		};

		/// groups some context parameters for processing http request
		struct processing_context
		{
			socket_streambuf sock; // socket where http request came from

			unsigned state_ver = 0; // current context state version

			// should this connection be closed after request processed, determined by Connection header,
			// but also - were there errors while processing request.
			connection_type conn = close;

			std::vector<const http_server_handler *> handlers; // http handlers registered in server
			std::vector<const http_pre_filter *> prefilters;   // http filters registered in server, sorted by order
			std::vector<const http_post_filter *> postfilters; // http filters registered in server, sorted by order

			http_request request;     // current http request, valid after is was parsed
			process_result response;  // current http response, valid after handler was called

			ssl_ctx_iptr ssl_ctx = nullptr; // ssl context, obtained from listener, where connection originated
			std::atomic<ext::shared_state_basic *> m_executor_state = nullptr; // holds current pending async execution, used for internal synchronization
		};

	protected:
		socket_queue m_sock_queue; // intenal socket and listener queue
		boost::container::flat_set<socket_streambuf::handle_type> m_sock_handles; // set of current pending sockets, used to detect new connections
		boost::container::flat_map<std::string, listener_context> m_listener_contexts; // listener contexts map by <addr:port>

		unsigned m_state_ver = 0;
		std::vector<std::unique_ptr<const http_server_handler>> m_handlers; // registered http handlers
		std::vector<ext::intrusive_ptr<http_pre_filter>> m_prefilters;      // registered http filters, unspecified order
		std::vector<ext::intrusive_ptr<http_post_filter>> m_postfilters;    // registered http filters, unspecified order

		ext::library_logger::logger * m_logger = nullptr;
		// log level on which http request and reply headers are logged
		unsigned m_request_logging_level = -1;
		// log level on which http request and reply body are logger, overrides m_request_logging_level if bigger
		unsigned m_request_body_logging_level = -1;

		// processing_contexts
		std::size_t m_minimum_contexts = 10;
		std::size_t m_maximum_contexts = 128;
		// set of existing contexts
		boost::container::flat_set<processing_context *> m_processing_contexts;
		// free contexts that can be reused
		std::vector<processing_context *> m_free_contexts;

		mutable std::mutex m_mutex;
		mutable std::condition_variable m_event;
		mutable std::thread m_thread;
		std::thread::id m_threadid; // id of thread running tasks and socket queue

		// linked list of task
		task_list m_tasks;
		// delayed tasks are little tricky, for every one - we create a service continuation,
		// which when fired, adds task to task_list.
		// Those can work and fire when we are being destructed,
		// http_server lifetime should not linger on delayed_task - they should become abandoned.
		// Nevertheless we have lifetime problem.
		//
		// So we store those active service continuations in a list:
		//  - When continuation is fired it checks if it's taken(future internal helper flag):
		//    * if yes - http_server is gone, nothing to do;
		//    * if not - http_server is still there - we should add task to a list;
		//
		//  - When destructing we are checking each continuation if it's taken(future internal helper flag):
		//   * if successful - service continuation is sort of cancelled and it will not access http_server
		//   * if not - continuation is firing right now somewhere in the middle,
		//     so destructor must wait until it finishes and then complete destruction.
		delayed_async_executor_task_continuation_list m_delayed;
		// how many delayed_continuations were not "taken/cancelled" at destruction,
		// and how many we must wait - it's sort of a semaphore.
		std::size_t m_delayed_count = 0;

		// optional http request processing executor
		std::shared_ptr<processing_executor> m_processing_executor;

		// http_server running state variables
		bool m_running = false;
		bool m_started = false;
		bool m_joined  = false;

		// listeners default backlog
		int m_default_backlog = 10;
		/// socket HTTP request processing operations(read/write) timeout
		duration_type m_socket_timeout = std::chrono::seconds(10);
		/// how long socket can be kept open awaiting new incoming HTTP requests
		duration_type m_keep_alive_timeout = m_sock_queue.get_default_timeout();
		/// timeout for socket operations when closing, basicly affects SSL shutdown
		static constexpr duration_type m_close_socket_timeout = std::chrono::milliseconds(100);

	protected:
		/// Performs actual startup of http server, blocking
		virtual void do_start(std::unique_lock<std::mutex> & lk);
		/// Performs actual stopping of http server, blocking
		virtual void do_stop (std::unique_lock<std::mutex> & lk);
		/// Resets http server to default state: closes all sockets, deletes handlers, filters.
		/// Some properties are not reset
		virtual void do_reset(std::unique_lock<std::mutex> & lk);

	public:
		/// Starts http_server: internal background thread + listeners start listen
		virtual void start();
		/// Stops http_server: background thread stopped, all sockets are closed, all http handlers, filters are deleted
		virtual void stop();

		/// Similar to start, but callers thread becomes background one and caller basicly joins it.
		/// Useful for simple configurations were you start https_server from main thread
		virtual void join_thread();
		/// Similar to stop, but must be called if http_server was started via join_thread.
		/// Can be called from signal handler.
		virtual void interrupt();

	protected:
		/// sort of union of bellow methods;
		class handle_method_type;

		using async_handle_method     = auto (http_server::*)(processing_context * context, ext::intrusive_ptr<ext::shared_state_basic> ptr) -> handle_method_type;
		using regular_handle_methed   = auto (http_server::*)(processing_context * context) -> handle_method_type ;
		using finalizer_handle_method = void (http_server::*)(processing_context * context);

	protected:
		/// Main background thread function, started_promise can be used to propagate exceptions to caller, and notify when actual startup is complete
		virtual void run_proc(ext::promise<void> & started_promise);
		/// Runs socket_queue until it interrupted.
		virtual void run_sockqueue();
		/// Reads, parses, process http request and writes http_response back, full cycle for single http request on socket.
		virtual void run_socket(processing_context * context);

		/// Starts and runs handle_* circuit next_method is initial method - handle_request if not overridden
		virtual void executor_method_runner(handle_method_type next_method, processing_context * context);
		/// Submits and schedules processing of async result, currently async http handler
		virtual void submit_async_executor_task(ext::intrusive_ptr<ext::shared_state_basic> handle, handle_method_type method, processing_context * context);
		/// Helper method for creating async handle_method
		static  auto async_method(ext::intrusive_ptr<ext::shared_state_basic> future_handle, async_handle_method async_method) -> handle_method_type;

		// http_request processing parts
		virtual auto handle_request(processing_context * context) -> handle_method_type;
		virtual auto handle_prefilters(processing_context * context) -> handle_method_type;
		virtual auto handle_processing(processing_context * context) -> handle_method_type;
		virtual auto handle_processing_result(processing_context * context) -> handle_method_type;
		virtual auto handle_async_processing_result(processing_context * context, ext::intrusive_ptr<ext::shared_state_basic> resp_handle) -> handle_method_type;
		virtual auto handle_postfilters(processing_context * context) -> handle_method_type;
		virtual auto handle_response(processing_context * context) -> handle_method_type;
		virtual void handle_finish(processing_context * context);

		/// Acquires processing context, one of cached ones, or creates one if allowed. If exhausted - returns null
		virtual auto acquire_context() -> processing_context *;
		/// Release processing context after http request processed, this method should place this context to cache or delete it, if cache is full
		virtual void release_context(processing_context * context);
		/// Prepares processing context, called each time new http request should be processed.
		/// Makes http handlers, filters snapshot if needed.
		virtual void prepare_context(processing_context * context, socket_streambuf sock, bool newconn);
		/// Called when processing context is created, default implementation does nothing
		virtual void construct_context(processing_context * context);
		/// Called when processing context is deleted, default implementation does nothing
		virtual void destruct_context(processing_context * context);

		/// Submits connection into socket_queue, also sets m_keep_alive_timeout on socket. Should be called from background thread
		virtual void submit_connection(socket_streambuf sock);
		/// Closes connection, logs, does some internal cleanup. Should be called from background thread
		virtual void close_connection(socket_streambuf sock);

		/// Called to configure newly accepted socket, called from executor(from handle_request).
		/// Currently it checks and configures SSL if needed.
		virtual bool configure_accepted_socket(socket_streambuf & sock, ssl_ctx_iptr ssl_ctx) const;
		/// Parses http request from socket, returns parsed request, or logs error and returns err status
		virtual auto parse_request(socket_streambuf & sock) const -> std::tuple<http_parse_result, http_request>;
		/// Writes http response to socket, if errors occurs, logs it and returns false
		virtual bool write_response(socket_streambuf & sock, const http_response & resp) const;
		/// Postprocess ready http response, can be used to do some http headers machinery,
		/// called after all http filter are handled, just before writting response.
		/// Also called for special answers created via create_*_response.
		/// Default implementation tweaks Close and Content-Length
		virtual void postprocess_response(http_response & resp) const;

		/// Exception wrapper for handler.process(request), on exception returns create_internal_server_error_response(sock, request, ex)
		virtual auto process_request(socket_streambuf & sock, const http_server_handler & handler, http_request & request) -> process_result;
		/// Exception wrapper for getting result from ext::future<http_response>, on exception returns create_internal_server_error_response(sock, request, ex).
		/// Also checks if future is cancelled or abandoned.
		virtual auto process_ready_response(async_process_result result, socket_streambuf & sock, http_request & request) -> http_response;

		/// Searches listener context by sock addr: from what listener does this socket came
		virtual const listener_context & get_listener_context(const socket_streambuf & sock) const;
		/// Searches acceptable http handler, nullptr if not found
		virtual const http_server_handler * find_handler(processing_context & context) const;

	protected:
		template <class Lock>
		void process_tasks(Lock & lock);

		template <class Lock, class Task>
		auto submit_task(Lock & lk, Task && task) -> ext::future<std::invoke_result_t<std::decay_t<Task>>>;

		template <class Task>
		auto submit_task(Task && task) -> ext::future<std::invoke_result_t<std::decay_t<Task>>>;

	protected:
		virtual auto do_add_listener(listener listener, int backlog, ssl_ctx_iptr ssl_ctx) -> ext::future<void>;
		virtual void do_add_handler(std::unique_ptr<const http_server_handler> handler);
		virtual void do_add_filter(ext::intrusive_ptr<http_filter_base> filter);
		//virtual void do_remove_handler(std::string uri, std::vector<std::string> methods);

	protected:
		/// Logs http request, checks log levels
		virtual void log_request(const http_request & request) const;
		/// Logs http response, checks log levels
		virtual void log_response(const http_response & response) const;
		/// Formats error from error codes, in case of SSL error reads and formats all SSL errors from OpenSSL error queue
		virtual std::string format_error(std::error_code errc) const;

		/// Creates HTTP 400 BAD REQUEST answer
		virtual http_response create_bad_request_response(socket_streambuf & sock, connection_type conn = close) const;
		/// Creates HTTP 503 Service Unavailable answer
		virtual http_response create_server_busy_response(socket_streambuf & sock, connection_type conn = close) const;
		/// Creates HTTP 404 Not found answer
		virtual http_response create_unknown_request_response(socket_streambuf & sock, const http_request & request) const;
		/// Creates HTTP 500 Internal Server Error answer, body = Request processing abandoned
		virtual http_response create_processing_abondoned_response(socket_streambuf & sock, const http_request & request) const;
		/// Creates HTTP 404 Canceled, body = Request processing cancelled
		virtual http_response create_processing_cancelled_response(socket_streambuf & sock, const http_request & request) const;
		/// Creates HTTP 500 Internal Server Error answer
		virtual http_response create_internal_server_error_response(socket_streambuf & sock, const http_request & request, std::exception * ex) const;

	public:
		/// Adds http filter(both pre and post if applicable)
		virtual void add_filter(ext::intrusive_ptr<http_filter_base> filter);
		/// Adds listener with optional SSL configuration
		virtual void add_listener(listener listener, ssl_ctx_iptr ssl_ctx = nullptr);
		/// Adds and opens listener by port number with optional SSL configuration
		virtual void add_listener(unsigned short port, ssl_ctx_iptr ssl_ctx = nullptr);
		/// Adds opens listener with given backlog with optional SSL configuration
		virtual void add_listener(listener listener, int backlog, ssl_ctx_iptr ssl_ctx = nullptr);
		/// Adds and opens listener by port number with given backlog and optional SSL configuration
		virtual void add_listener(unsigned short port, int backlog, ssl_ctx_iptr ssl_ctx = nullptr);

		/// Adds http handler
		virtual void add_handler(std::unique_ptr<const http_server_handler> handler);
		/// Adds simple http handler
		virtual void add_handler(std::vector<std::string> methods, std::string url, function_type function);
		/// Adds simple http handler
		virtual void add_handler(std::string url, function_type function);
		/// Adds simple http handler
		virtual void add_handler(std::string method, std::string url, function_type function);

	public:
		/// Configures processing context limits
		virtual void set_processing_context_limits(std::size_t minimum, std::size_t maximum);
		/// Sets http processing executor
		virtual void set_processing_executor(std::shared_ptr<processing_executor> executor);
		/// Sets http processing executor to given thread_pool
		virtual void set_thread_pool(std::shared_ptr<ext::thread_pool> pool);

	public:
		void set_socket_timeout(duration_type timeout);
		auto get_socket_timeout() const -> duration_type;

		void set_keep_alive_timeout(duration_type timeout);
		auto get_keep_alive_timeout() const -> duration_type;

	public:
		void set_logger(ext::library_logger::logger * logger, bool log_internals = false) { m_logger = logger; if (log_internals) m_sock_queue.set_logger(logger); }
		auto get_logger() const noexcept { return m_logger;   }

		void set_request_logging_level(unsigned log_level) { m_request_logging_level = log_level; }
		auto get_request_logging_level(unsigned log_level) { return m_request_logging_level; }

		void set_request_body_logging_level(unsigned log_level) { m_request_body_logging_level = log_level; }
		auto get_request_body_logging_level(unsigned log_level) { return m_request_body_logging_level; }

	public:
		http_server();
		virtual ~http_server();

		http_server(http_server && ) = delete;
		http_server & operator =(http_server && ) = delete;
	};

}
