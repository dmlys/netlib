#pragma once
#include <atomic>
#include <memory>
#include <chrono>
#include <algorithm>
#include <functional>
#include <tuple>
#include <list>

#include <ext/library_logger/logger.hpp>
#include <ext/net/socket_stream.hpp>
#include <ext/net/listener.hpp>



namespace ext::net
{
	/// NOTE: this is very simple class, it can be used is some trivial/simple applications, in other cases you should use more adequate solution.
	/// socket_queue class manages and allows waiting on set of sockets and listeners in a queue fashion.
	/// It have 2 sets: sockets and listeners. Both are waited to be readable/writable with select/poll system call.
	/// When select/poll finishes waiting:
	/// * check listeners and if there are pending connections - accept then, submit to queue end
	/// * check sockets from queue, find first ready one remove it from queue, return to client
	///   remember next position, next search starts from it, that way socket are treated in fair way
	///
	/// This class is not thread safe, except interrupt method, which can be called from any thread or signal handler.
	class socket_queue
	{
		struct helper; friend helper;

	public:
		/// result of wait operation
		enum wait_status : unsigned
		{
			ready,         /// there is ready socket, it can be ready, have error or timeout(ext::net::sock_errc::timeout
			timeout,       /// no ready sockets for given timeout/until given time point(wait_for/wait_until)
			               /// NOTE: this does not mean that some socket timed out.
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
			socket_streambuf sock;        /// pending socket
			time_point       submit_time; /// time point of socket submission into this queue
			handle_type      listener;    /// if new socket, holds handle to a listener from which this socket was accepted
			wait_type        wtype;       /// socket wait type: readable, writable or both

			unsigned ready        : 1; /// ready status flag
			unsigned ready_status : 2; /// ready status wait_status::ready or wait_status::timeout
		};

		using sock_list = std::list<item>;
		using listener_list = std::list<ext::net::listener>;

	private:
		sock_list m_socks;
		listener_list m_listeners;

		/// current position in socket queue list, where search should be started
		sock_list::iterator m_cur = m_socks.begin();
		/// Holds item.listener for last socket retrieved with take method.
		/// This handle is valid for sockets accepted from listeners in this queue
		handle_type m_last_accepted_socket_listener;

		/// interruption flag
		std::atomic_bool m_interrupted = ATOMIC_VAR_INIT(false);
		/// pipe pair used to interrupt blocking select/poll syscall
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
		/// finds ready socket in given range, returns iterator to it
		auto find_ready_socket(sock_list::iterator first, sock_list::iterator last) -> sock_list::iterator;
		/// this is actually heart of this class, it searches for ready socket, if there are no such -
		/// creates socket sets for select/poll call - call it, process select/poll result, accepts new incoming connections from listeners, etc
		/// returns waiting result, and if there is ready socket - m_cur will point to it
		auto wait_ready(time_point until) -> wait_status;
		
	private:
		/// submits socket_streambuf for waiting: readable, writable or both
		void submit(socket_streambuf sock, handle_type listener, wait_type wtype);
		/// erases all bindings of socket items to listeners(nullifiers item.from_listener)
		void erase_listener_tracking();
		
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
		/// waits until some socket becomes ready for read or write(depends on submission flag) or have error, timed out; returns wait_status::ready with ready socket.
		/// with any other wait_status returned socket_streambuf will be empty: socket_streambuf::is_open == false
		auto take() -> std::tuple<wait_status, socket_streambuf>;
		/// submits socket_streambuf for waiting: readable, writable or both
		void submit(socket_streambuf sock, wait_type wtype = readable);
		/// submits socket_stream from socket_stream for waiting: readable, writable or both.
		/// socket_stream itself is discarded and destroyed
		void submit(socket_stream    sock, wait_type wtype = readable);
		
	public:
		/// lasl - last accepted socket listener.
		/// If last taken socket was accepted from one of listeners in this queue, this method will return that listener, otherwise invalid_handle.
		/// Calling this method only allowed after successful take call(wait_status == ready), otherwise calling this method is undefined behaviour.
		handle_type lasl() const { return m_last_accepted_socket_listener; }
		
	public:
		/// queue is empty if it does not have any listeners or sockets
		bool empty() const noexcept { return m_listeners.empty() and m_socks.empty(); }
		/// clears this queue, closes any listeners and sockets currently present in this queue
		void clear() noexcept;

	public:
		/// adds listener to socket_queue, new incoming connections will be automatically submitted with readable while wait*/take calls takes place
		void add_listener(ext::net::listener listener);
		/// removes and returns listener with specified port
		auto remove_listener(unsigned short port) -> ext::net::listener;
		auto take_listener(unsigned short port) -> ext::net::listener { return remove_listener(port); }

		auto get_listeners() const -> const listener_list & { return m_listeners; }
		auto get_listeners()       ->       listener_list & { erase_listener_tracking(); return m_listeners; }
		auto take_listeners()      ->       listener_list   { erase_listener_tracking(); return std::move(m_listeners); }
		auto take_sockets()        ->       std::vector<socket_streambuf>;

	public:
		/// sets/gets default timeout for newly accepted sockets from listeners
		void set_default_timeout(duration_type timeout) { m_timeout = timeout; }
		auto get_default_timeout() const noexcept       { return m_timeout;    }

	public:
		void set_logger(ext::library_logger::logger * logger) { m_logger = logger; }
		auto get_logger() const noexcept                      { return m_logger;   }

	public:
		socket_queue();
		~socket_queue();

		socket_queue(socket_queue &&) noexcept;
		socket_queue & operator =(socket_queue &&) noexcept;

		socket_queue(const socket_queue &) = delete;
		socket_queue & operator =(const socket_queue &) = delete;
	};
}
