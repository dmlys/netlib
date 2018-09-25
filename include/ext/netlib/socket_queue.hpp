#pragma once
#include <atomic>
#include <memory>
#include <chrono>
#include <algorithm>
#include <functional>
#include <tuple>
#include <list>

#include <ext/library_logger/logger.hpp>
#include <ext/iostreams/socket_stream.hpp>
#include <ext/netlib/listener.hpp>



namespace ext::netlib
{
	/// socket_queue class manages and allows waiting on set of sockets and listeners in a queue fashion.
	/// It have 2 sets: sockets and listeners. Both are waited to be readable/writable with select system call.
	/// When select finishes waiting:
	/// * check listeners and if there are pending connections - accept then, submit to queue end
	/// * check sockets from queue, find first ready one remove it from queue, return to client
	///   remember next position, next search start from it, that way socket are treated in fair way
	///
	/// This class is not thread safe, except interrupt method, which can be called from any thread or signal handler
	class socket_queue
	{
		struct helper; friend helper;

	public:
		/// result of wait operation
		enum wait_status : unsigned
		{
			ready,         /// there is ready socket
			timeout,       /// no ready sockets for given timeout/until given time point(wait_for/wait_until)
			empty_queue,   /// queue is empty - there are no sockets and listeners
			interrupted,   /// wait operation was interrupted via interrupt parallel call
		};

		/// socket state wait flag
		enum wait_type : unsigned
		{
			readable = 1,                /// wait socket become readable
			writable = 2,                /// wait socket become writable
			both = readable | writable   /// wait socket become readable or writable
		};

		using handle_type   = socket_streambuf::handle_type;
		using duration_type = std::chrono::steady_clock::duration;
		using time_point    = std::chrono::steady_clock::time_point;

	private:
		struct item
		{
			socket_streambuf sock;   /// pending socket
			wait_type  wtype;        /// socket wait type: readable, writable or both
			time_point submit_time;  /// time point of socket submission into this queue
		};

		using sock_list = std::list<item>;
		using listener_list = std::list<ext::netlib::listener>;

	private:
		sock_list m_socks;
		listener_list m_listeners;

		/// current position in socket queue list, where search should be started
		sock_list::iterator m_cur = m_socks.begin();

		/// interruption flag
		std::atomic_bool m_interrupted = ATOMIC_VAR_INIT(false);
		/// pipe pair used to interrupt blocking select syscall
		handle_type m_interrupt_listen = -1;
		handle_type m_interrupt_write  = -1;
		/// default timeout for newly accepted sockets
		duration_type m_timeout = duration_type::max();
		/// optional logger for some diagnostic, debug stuff
		ext::library_logger::logger * m_logger = nullptr;

	private:
		/// does initial socket configuration after accept from listener
		void configure(socket_streambuf & sock);
		/// consumes all input from given socket handle
		void consume_all_input(handle_type sock);
		/// manages object state after interrupt event, does some clean up and stuff
		auto process_interrupted();

		/// searches ready socket from m_socks list via socket_streambuf::in_avail( ::ioctl(..., FIONREAD, ...) syscall )
		/// if there is no such returns m_socks.end()
		auto find_ready_socket(time_point now) -> sock_list::iterator;
		/// this is actually heart of this class, it searches for ready socket, if there are no such -
		/// creates socket sets for select call - call it, process select result, accepts new incoming connections from listeners, etc
		/// returns waiting result, and if there is ready socket - m_cur will point to it
		auto wait_ready(time_point until) -> wait_status;

	public:
		/// waits until some socket becomes ready for read or write(depends on submission flag).
		wait_status wait() const;		
		/// waits until some socket becomes ready for read or write(depends on submission flag),
		/// it block until specified timeout duration has elapsed or result became available(or interrupt happened),
		/// whichever comes first.
		wait_status wait_for(duration_type timeout) const;
		/// waits until some socket becomes ready for read or write(depends on submission flag),
		/// it block until specified time point reached or result became available(or interrupt happened),
		/// whichever comes first.
		wait_status wait_until(time_point point) const;

		/// if there is blocking wait*/take operation in progress - interrupts it, that operation will return wait_status::interrupted code
		/// if there is now such operation right now - next call to wait*/take will return wait_status::interrupted
		void interrupt();

	public:
		/// waits until some socket becomes ready for read or write(depends on submission flag) and returns wait_status::ready with ready socket it.
		/// with any other wait_status returned socket_streambuf will be empty: socket_streambuf::is_open == false
		auto take() -> std::tuple<wait_status, socket_streambuf>;
		/// submits socket_streambuf for waiting: readable, writable or both
		void submit(socket_streambuf sock, wait_type wtype = readable);
		/// submits socket_stream from socket_stream for waiting: readable, writable or both.
		/// socket_stream itself is discarded and destroyed
		void submit(socket_stream    sock, wait_type wtype = readable);

	public:
		/// adds listener to socket_queue, new incoming connections will be automatically submitted with readable while wait*/take calls takes place
		void add_listener(ext::netlib::listener listener);
		/// removes and returns listener with specified port
		auto remove_listener(unsigned short port) -> ext::netlib::listener;
		auto take_listener(unsigned short port) -> ext::netlib::listener { return remove_listener(port); }

		auto get_listeners() const -> const listener_list &;
		auto take_listeners() -> listener_list;

	public:
		/// sets/gets default timeout for newly accepted sockets from listeners
		void set_default_timeout(duration_type timeout) { m_timeout = timeout; }
		auto get_default_timeout() const noexcept       { return m_timeout;    }

	public:
		void set_logger(ext::library_logger::logger * logger) { m_logger = logger; }
		auto get_logger()                                     { return m_logger;   }

	public:
		socket_queue();
		~socket_queue();

		socket_queue(socket_queue &&) noexcept;
		socket_queue & operator =(socket_queue &&) noexcept;

		socket_queue(const socket_queue &) = delete;
		socket_queue & operator =(const socket_queue &) = delete;
	};
}
