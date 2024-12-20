﻿#pragma once
#include <memory>
#include <string>
#include <vector>
#include <variant>

#include <thread>
#include <mutex>
#include <condition_variable>

#include <boost/container/flat_set.hpp>
#include <boost/container/flat_map.hpp>

#include <ext/config.hpp>
#include <ext/future.hpp>
#include <ext/thread_pool.hpp>
#include <ext/intrusive_ptr.hpp>
#include <ext/log/logger.hpp>
#include <ext/stream_filtering/filter_types.hpp>

#include <ext/openssl.hpp>
#include <ext/net/socket_base.hpp>
#include <ext/net/socket_queue.hpp>

#include <ext/net/http/http_parser.hpp>
#include <ext/net/http/http_types.hpp>
#include <ext/net/http/http_server_handler.hpp>
#include <ext/net/http/http_server_filter.hpp>
#include <ext/net/http/nonblocking_http_parser.hpp>
#include <ext/net/http/nonblocking_http_writer.hpp>


namespace ext::net::http
{
	/// Simple embedded http server.
	/// Listens for incoming connections on given listener sockets,
	/// parses http requests, calls registered handler that accepts that request
	///
	/// supports:
	/// * SSL
	/// * http_handlers: sync and async(result is returned via ext::future)
	/// * http_filters
	/// * thread_pool executor
	///
	/// have 2 working modes(those should not be mixed):
	///  * work on current thread(join/interrupt), useful when you want start simple http_server on main thread
	///  * work on internal background thread(start/stop), useful when you do not want block main thread in http_server
	///
	/// NOTE: by default there no preinstalled filters or handlers
	class http_server
	{
		using self_type = http_server;

	public:
		using socket_queue  = ext::net::socket_queue;
		using handle_type   = socket_queue::handle_type;
		using duration_type = socket_queue::duration_type;
		using time_point    = socket_queue::time_point;

		using handler_result_type = http_server_handler::result_type;
		using simple_handler_result_type = simple_http_server_handler::result_type;
		using simple_handler_body_function_type = simple_http_server_handler::body_function_types;
		using simple_handler_request_function_type = simple_http_server_handler::request_function_type;

#ifdef EXT_ENABLE_OPENSSL
		//using SSL          = ::SSL;
		using ssl_ctx_iptr = ext::openssl::ssl_ctx_iptr;
		using ssl_iptr     = ext::openssl::ssl_iptr;
#else
		//using SSL          = std::nullptr_t;
		using ssl_ctx_iptr = std::nullptr_t;
		using ssl_iptr     = std::nullptr_t;
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
		//  In case of async - special continuation is attached to returned future, it submits special task when http_result future become ready.
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
		// handle_* group:
		//  http request is handled by handle_* method group. All methods can be overridden, also to allow more customization, each method returns what must be done next:
		//   ... -> handle_request -> handle_prefilters -> .... -> handle_finish
		
	protected:
		using process_result = http_server_handler::result_type;
		using async_process_result = std::variant<ext::future<http_response>, ext::future<null_response_type>>;

		class task_base; // inherits hook_type
		template <class Functor, class ResultType>
		class task_impl; // implements task_base
		class delayed_async_executor_task_continuation;

		class processing_executor;
		template <class ExecutorPtr>
		class processing_executor_impl;

		class closable_http_body;
		class async_http_body_source_impl;
		class http_body_streambuf_impl;

	protected:
		using hook_type = boost::intrusive::list_base_hook<
			boost::intrusive::link_mode<boost::intrusive::link_mode_type::normal_link>
		>;
		
		using list_option = boost::intrusive::base_hook<hook_type>;
		using task_list = boost::intrusive::list<task_base, list_option, boost::intrusive::constant_time_size<false>>;
		using delayed_async_executor_task_continuation_list = boost::intrusive::list<delayed_async_executor_task_continuation, list_option, boost::intrusive::constant_time_size<false>>;

	protected:
		struct processing_context;
		class  http_server_control;

		/// sort of union of bellow methods;
		class handle_method_type;

		using regular_handle_methed   = auto (http_server::*)(processing_context * context) -> handle_method_type ;
		using finalizer_handle_method = void (http_server::*)(processing_context * context);

	protected:
		using property_map = boost::container::flat_map<std::string, http::http_server_control::property>;
		using streaming_context = ext::stream_filtering::streaming_context
		<
			std::vector<std::unique_ptr<ext::stream_filtering::filter>>, // FilterVector
			std::vector<ext::stream_filtering::data_context>,            // DataContextVector
			std::vector<std::vector<char>>                               // BuffersVector
		>;
		
		/// holds some listener context configuration
		struct listener_context
		{
			unsigned backlog;
			ssl_ctx_iptr ssl_ctx;
			ext::net::listener listener;
		};
		
		struct config_context;
		struct filtering_context;
		
		struct filtering_context
		{
			streaming_context request_streaming_ctx, response_streaming_ctx;
			ext::stream_filtering::processing_parameters filter_params;
		};
		
		struct processing_context_deleter
		{
			http_server * server;
			void operator()(processing_context * context) const noexcept { return server->destroy_context(context); }
		};
		
		using processing_context_uptr = std::unique_ptr<processing_context, processing_context_deleter>;
		
	protected:
		socket_queue m_sock_queue; // intenal socket and listener queue
		boost::container::flat_map<handle_type, listener_context> m_listener_contexts; // listener contexts map by listener handle
		
		// sharable COW config context, see config_context description
		std::shared_ptr<config_context> m_config_context;// = std::make_shared<config_context>();

		ext::log::logger * m_logger = nullptr;
		// log level on which http request and reply headers are logged
		unsigned m_request_logging_level = -1;
		// log level on which http request and reply body are logger, overrides m_request_logging_level if higher
		unsigned m_request_body_logging_level = -1;
		// log level on which every read from socket operation buffer is logged
		unsigned m_read_buffer_logging_level = -1;
		// log level on which every write to socket operation buffer is logged
		unsigned m_write_buffer_logging_level = -1;

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

		// linked list of tasks
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
		bool m_running = false;     // http_server is in running state
		bool m_started = false;     // http_server is started either by start or join
		bool m_joined  = false;     // used only by join/interrupt pair methods
		bool m_interrupted = false; // used only by join/interrupt pair methods
		bool m_destructed = false;  // this object destruction was already performed, see destruct method

		// listeners default backlog
		int m_default_backlog = 10;
		/// socket processing operations(read/write) timeout
		duration_type m_socket_timeout = std::chrono::seconds(10);
		/// how long socket can be kept open awaiting new incoming HTTP requests
		duration_type m_keep_alive_timeout = duration_type::max();
		/// timeout for socket operations when closing, basicly affects SSL shutdown
		static constexpr duration_type m_close_socket_timeout = std::chrono::milliseconds(100);

		/// constant helpers
		static constexpr auto chunkprefix_size = sizeof(int) * CHAR_BIT / 4 + (CHAR_BIT % 4 ? 1 : 0); // Transfer-Encoding: chunked, chunk header(hex) size
		static constexpr std::string_view crlf = "\r\n";
		static const     std::error_code success_errc; // = {} success error constant
		
	protected:
		/// Destroys this object, basicly a destructor implementation.
		/// Current implementation of destructor calls do_reset, do_stop methods and those call other virtual methods.
		/// Thats actually is a problem, cause in c++ in constructor and destructor, virtual methods dispatch is suppressed.
		/// 
		/// The thing is I want those methods to be virtual, and they should be called from destructor. But language wise nothing can be done.
		/// Instead special boolean member flag is introduced - destroyed, if it's false - destructor should proceed, otherwise - object already destroyed.
		/// This method is default destructor implementation + checking m_destroyed member.
		/// 
		/// Now derived class can override some method, call destruct from derived class destructor. And this class destructor will do nothing instead
		virtual void destruct();
		
	protected:
		/// Performs actual startup of http server, blocking
		virtual void do_start(std::unique_lock<std::mutex> & lk);
		/// Performs actual stopping of http server, blocking
		virtual void do_stop (std::unique_lock<std::mutex> & lk);
		/// Resets http server to default state: closes all sockets, deletes handlers, filters.
		/// Some properties are not reset
		virtual void do_reset(std::unique_lock<std::mutex> & lk);
		/// clears m_config_context
		virtual void do_clear_config(std::unique_lock<std::mutex> & lk);

	public:
		/// Starts http_server: internal background thread + listeners start listen
		virtual void start();
		/// Stops http_server: background thread stopped, all sockets are closed, all http handlers, filters are deleted
		virtual void stop();

		/// Similar to start, but callers thread becomes background one and caller basicly joins it.
		/// Useful for simple configurations were you start https_server from main thread
		virtual void join();
		/// Similar to stop, but must be called if http_server was started via join.
		/// Can be called from signal handler.
		virtual void interrupt();

	protected:
		/// Main background thread function, started_promise can be used to propagate exceptions to caller, and notify when actual startup is complete
		virtual void run_proc(ext::promise<void> & started_promise);
		/// Runs socket_queue until it interrupted.
		virtual void run_sockqueue();
		/// Process ready socket, called for each socket taken from socket_queue in run_sockqueue method.
		/// Context is associated with socket, if socket is new - context we be null.
		/// socket_errc - socket error reported by socket queue, if any
		virtual void process_socket(ext::net::socket_uhandle usock, processing_context * socket_context, std::error_code socket_errc);
		/// Reads, parses, process http request and writes http_response back, full cycle for single http request on socket.
		virtual void run_socket(processing_context * context);
		
		/// Runs handle_* circuit, updates context->cur_method for regular methods
		virtual void executor_handle_runner(handle_method_type next_method, processing_context * context);
		/// Submits and schedules processing of async result
		virtual void submit_async_executor_task(ext::intrusive_ptr<ext::shared_state_basic> handle, handle_method_type method, processing_context * context);
		/// Helper method for creating async handle_method
		static  auto async_method(ext::intrusive_ptr<ext::shared_state_basic> future_handle, regular_handle_methed async_method) -> handle_method_type;
		static  auto async_method(socket_queue::wait_type wait,                              regular_handle_methed async_method) -> handle_method_type;

		/// Checks if there is a pending ssl handshake on socket:
		///   peeks one byte available from socket via MSG_PEEK,
		///   and checks it start on ssl handshake packet( == 0x16)
		virtual bool pending_ssl_hanshake(handle_type sock);
		
		/// non blocking recv with MSG_PEEK:
		///  * if successfully reads something - returns nullptr
		///  * if read would block - returns wait_connection operation,
		///  * if some error occurs - logs it and returns handle_finish
		virtual auto peek(processing_context * context, char * data, int len, int & read) const -> handle_method_type;
		/// non blocking recv method:
		///  * if successfully reads something - returns nullptr
		///  * if read would block - returns wait_connection operation,
		///  * if some error occurs - logs it and returns handle_finish
		virtual auto recv(processing_context * context, char * data, int len, int & read) const -> handle_method_type;
		/// non blocking send method:
		///  * if successfully sends something - returns nullptr
		///  * if send would block - returns wait_connection operation,
		///  * if some error occurs - logs it and returns handle_finish
		virtual auto send(processing_context * context, const char * data, int len, int & written) const -> handle_method_type;
		
		/// non blocking recv method, read data is parsed with http parser,
		/// result is stored in whatever parser body destination is set
		///  * if successfully reads something - returns nullptr
		///  * if read would block - returns wait_connection operation,
		///  * if some error occurs - logs it and returns handle_finish.
		virtual auto recv_and_parse(processing_context * context) const -> handle_method_type;
		/// same as recv_and_parse, but no more than limit is ever read from socket in total,
		/// otherwise bad response is created and http_server::handle_response is returned, connection is closed.
		virtual auto recv_and_parse(processing_context * context, std::size_t limit) const -> handle_method_type;
		
		/// returns socket recv buffer size getsockopt(..., SOL_SOCKET, SO_RCVBUF, ...), but no more that 10 * 1024
		virtual std::size_t recvbuf_size(const handle_type sock) const;
		/// returns socket send buffer size getsockopt(..., SOL_SOCKET, SO_SNDBUF, ...), but no more that 10 * 1024
		virtual std::size_t sendbuf_size(const handle_type sock) const;

	protected:
		// http_request processing parts
		virtual auto handle_start(processing_context * context) -> handle_method_type;
		virtual auto handle_end_processing(processing_context * context) -> handle_method_type;
		virtual void handle_finish(processing_context * context);
		
		virtual auto handle_ssl_configuration(processing_context * context) -> handle_method_type;
		virtual auto handle_ssl_start_handshake(processing_context * context) -> handle_method_type;
		virtual auto handle_ssl_continue_handshake(processing_context * context) -> handle_method_type;
		virtual auto handle_ssl_finish_handshake(processing_context * context) -> handle_method_type;
		virtual auto handle_ssl_shutdown(processing_context * context) -> handle_method_type;

		virtual auto handle_request_headers_parsing(processing_context * context) -> handle_method_type;
		virtual auto handle_request_normal_body_parsing(processing_context * context) -> handle_method_type;
		virtual auto handle_request_filtered_body_parsing(processing_context * context) -> handle_method_type;
		virtual auto handle_discarded_request_body_parsing(processing_context * context) -> handle_method_type;
		virtual auto handle_request_normal_async_source_body_parsing(processing_context * context) -> handle_method_type;
		virtual auto handle_request_filtered_async_source_body_parsing(processing_context * context) -> handle_method_type;

		virtual auto handle_parsed_headers(processing_context * context) -> handle_method_type;
		virtual auto handle_prefilters(processing_context * context) -> handle_method_type;
		virtual auto handle_find_handler(processing_context * context) -> handle_method_type;
		virtual auto handle_request_header_processing(processing_context * context) -> handle_method_type;
		virtual auto handle_request_init_body_parsing(processing_context * context) -> handle_method_type;

		virtual auto handle_parsed_request(processing_context * context) -> handle_method_type;
		virtual auto handle_processing(processing_context * context) -> handle_method_type;
		virtual auto handle_processing_result(processing_context * context) -> handle_method_type;
		virtual auto handle_postfilters(processing_context * context) -> handle_method_type;

		virtual auto handle_response(processing_context * context) -> handle_method_type;
		virtual auto handle_response_headers_writting(processing_context * context) -> handle_method_type;
		virtual auto handle_response_headers_written(processing_context * context) -> handle_method_type;
		
		virtual auto handle_response_normal_body_writting(processing_context * context) -> handle_method_type;
		virtual auto handle_response_filtered_body_writting(processing_context * context) -> handle_method_type;
		virtual auto handle_response_lstream_body_writting(processing_context * context) -> handle_method_type;
		virtual auto handle_response_normal_stream_body_writting(processing_context * context) -> handle_method_type;
		virtual auto handle_response_filtered_stream_body_writting(processing_context * context) -> handle_method_type;
		virtual auto handle_response_normal_async_body_writting(processing_context * context) -> handle_method_type;
		virtual auto handle_response_filtered_async_body_writting(processing_context * context) -> handle_method_type;
		
		virtual auto handle_response_written(processing_context * context) -> handle_method_type;
		virtual auto handle_cleanup_and_finish(processing_context * context) -> handle_method_type;

	protected: // filtering
		virtual void prepare_request_http_body_filtering(processing_context * context);
		virtual void filter_request_http_body(processing_context * context);

		virtual void prepare_response_http_body_filtering(processing_context * context);
		virtual void filter_response_http_body(processing_context * context);
		
	protected:
		/// Called when processing context is allocated, default implementation just allocates it
		virtual auto allocate_context() -> processing_context *;
		/// Called when processing context is deallocated, default implementation just allocates deallocates
		virtual void destroy_context(processing_context * context) noexcept;
		
		/// Acquires processing context, one of cached ones, or creates one if allowed. If exhausted - returns null
		virtual auto acquire_context() -> processing_context *;
		/// Release processing context after http request processed, this method should place this context to cache or delete it, if cache is full
		virtual void release_context(processing_context * context);
		
		/// Prepares processing context, called each time new http request should be processed.
		/// Makes http handlers and filters snapshots if needed.
		virtual void prepare_context(processing_context * context);
		/// Cleans proccessing context, called each time after http request is processed
		/// clears some members, resets collections, etc
		virtual void cleanup_context(processing_context * context);
		
		/// Submits socket into internal socket_queue for waiting socket event(readable/writable).
		/// When socket will become ready, processing will continue from where it stopped.
		/// Should be called from server background thread
		virtual void wait_connection(processing_context * context);
		/// Submits connection into socket_queue, also sets m_keep_alive_timeout on socket. Should be called from server background thread
		virtual void submit_connection(processing_context * context);
		/// Shutdowns socket(::shutdown) depending on processing_context
		virtual void shutdown_connection(processing_context * context);
		/// Closes socket connection and release context into processing context pool.
		/// Socket closing is done via close_connection
		virtual void release_connection(processing_context * context, const std::error_code & sock_err = success_errc);
		/// Closes connection, logs, does some internal cleanup. Should be called from server background thread
		virtual void close_connection(ext::net::socket_uhandle sock, const std::error_code & sock_err = success_errc);

		/// Writes http response to socket, if errors occurs, logs it and returns false
		//virtual bool write_response(handle_type sock, const http_response & resp) const;
		
		/// Postprocess ready http response, can be used to do some http headers machinery,
		/// called after all http filter are handled, just before writting response.
		/// Also called for special answers created via create_*_response.
		/// Default implementation tweaks Close and Content-Length
		virtual void postprocess_response(http_response & resp) const;
		virtual void postprocess_response(processing_context * context) const;
		
		/// Does some response checking, default implementation checks if request http body was fully parsed
		/// NOTE: postprocess_response is called separately
		virtual void check_response(processing_context * context) const;

		/// Exception wrapper for handler.process(context), on exception returns create_internal_server_error_response(sock, request, ex)
		virtual auto process_request(processing_context * context) -> process_result;
		/// Exception wrapper for getting result from ext::future<http_response>, on exception returns create_internal_server_error_response(sock, request, ex).
		/// Also checks if future is cancelled or abandoned.
		virtual auto process_ready_response(async_process_result result, const handle_type sock, http_request & request) -> process_result;

		/// Searches listener context by listener handle
		virtual const listener_context & get_listener_context(socket_handle_type listener_handle) const;
		/// Searches acceptable http handler, nullptr if not found
		virtual const http_server_handler * find_handler(processing_context & context) const;

	protected:
		template <class Lock>
		void process_tasks(Lock & lock);

		template <class Lock, class Task>
		auto submit_task(Lock & lk, Task && task) -> ext::future<std::invoke_result_t<std::decay_t<Task>>>;

		template <class Task>
		auto submit_task(Task && task) -> ext::future<std::invoke_result_t<std::decay_t<Task>>>;
		
		/// submits task for running handle_* circuit
		void submit_handler(handle_method_type next_method, processing_context * context);
		
		template <class Lock>
		void submit_handler(Lock & lk, handle_method_type next_method, processing_context * context);

	protected:
		/// obtains current config context, copying one if needed
		config_context & current_config();
		
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

		/// logs read buffer in hex dump format
		virtual void log_read_buffer(const handle_type sock_handle, const char * buffer, std::size_t size) const;
		/// logs write buffer in hex dump format
		virtual void log_write_buffer(const handle_type sock_handle, const char * buffer, std::size_t size) const;
		/// parses Accept header and returns text/plain and text/html weights
		static std::pair<double, double> parse_accept(const http_request & request);

		/// Creates HTTP 400 BAD REQUEST answer
		virtual http_response create_bad_request_response(const handle_type sock, connection_action_type conn = connection_action_type::close) const;
		/// Creates HTTP 503 Service Unavailable answer
		virtual http_response create_server_busy_response(const handle_type sock, connection_action_type conn = connection_action_type::close) const;
		/// Creates HTTP 404 Not found answer
		virtual http_response create_unknown_request_response(const handle_type sock, const http_request & request) const;
		/// Creates HTTP 500 Internal Server Error answer, body = Request processing abandoned
		virtual http_response create_processing_abondoned_response(const handle_type sock, const http_request & request) const;
		/// Creates HTTP 404 Canceled, body = Request processing cancelled
		virtual http_response create_processing_cancelled_response(const handle_type sock, const http_request & request) const;
		/// Creates HTTP 500 Internal Server Error answer
		virtual http_response create_internal_server_error_response(const handle_type sock, const http_request & request, std::exception * ex) const;
		/// Creates HTTP 417 Expectation Failed answer
		virtual http_response create_expectation_failed_response(const processing_context * context) const;
		/// Creates HTTP 100 Continue response
		virtual http_response create_continue_response(const processing_context * context) const;

	public:
		/// Adds http filter(both pre and post if applicable)
		virtual void add_filter(ext::intrusive_ptr<http_filter_base> filter);
		/// Adds listener with optional SSL configuration
		virtual void add_listener(listener listener, ssl_ctx_iptr ssl_ctx = nullptr);
		/// Adds opens listener with given backlog with optional SSL configuration
		virtual void add_listener(listener listener, int backlog, ssl_ctx_iptr ssl_ctx = nullptr);
		/// Adds and opens listener by port number with optional SSL configuration
		virtual void add_listener(unsigned short port, ssl_ctx_iptr ssl_ctx = nullptr);

		/// Adds http handler
		virtual void add_handler(std::unique_ptr<const http_server_handler> handler);
		/// Adds simple http handler
		virtual void add_handler(std::vector<std::string> methods, std::string url, simple_handler_body_function_type function);
		/// Adds simple http handler
		virtual void add_handler(std::string url, simple_handler_body_function_type function);
		/// Adds simple http handler
		virtual void add_handler(std::string method, std::string url, simple_handler_body_function_type function);
		/// Adds simple http handler
		virtual void add_handler(std::vector<std::string> methods, std::string url, simple_handler_request_function_type function, http_body_type wanted_request_body_type = http_body_type::string);
		/// Adds simple http handler
		virtual void add_handler(std::string url, simple_handler_request_function_type function, http_body_type wanted_request_body_type = http_body_type::string);
		/// Adds simple http handler
		virtual void add_handler(std::string method, std::string url, simple_handler_request_function_type function, http_body_type wanted_request_body_type = http_body_type::string);

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

	public: // limits
		void set_maximum_http_headers_size(unsigned size);
		auto get_maximum_http_headers_size() -> unsigned;
		
		void set_maximum_http_body_size(unsigned size);
		auto get_maximum_http_body_size() -> unsigned;
		
		void set_maximum_discarded_http_body_size(unsigned size);
		auto get_maximum_discarded_http_body_size() -> unsigned;
		
	public:
		void set_logger(ext::log::logger * logger) { m_logger = logger; m_sock_queue.set_logger(logger); }
		auto get_logger() const noexcept { return m_logger;   }

		void set_request_logging_level(unsigned log_level) noexcept { m_request_logging_level = log_level; }
		auto get_request_logging_level()             const noexcept { return m_request_logging_level; }

		void set_request_body_logging_level(unsigned log_level) noexcept { m_request_body_logging_level = log_level; }
		auto get_request_body_logging_level()             const noexcept { return m_request_body_logging_level; }

		void set_read_buffer_logging_level(unsigned log_level) noexcept { m_read_buffer_logging_level = log_level; }
		auto get_read_buffer_logging_level()             const noexcept { return m_read_buffer_logging_level; }

		void set_write_buffer_logging_level(unsigned log_level) noexcept { m_write_buffer_logging_level = log_level; }
		auto get_write_buffer_logging_level()             const noexcept { return m_write_buffer_logging_level; }

	public:
		http_server();
		virtual ~http_server();

		http_server(http_server && ) = delete;
		http_server & operator =(http_server && ) = delete;
	};

}
