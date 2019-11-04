#include <cstring>      // for std::memset and stuff
#include <memory>

#include <fmt/format.h>

#include <ext/config.hpp>
#include <ext/utility.hpp>
#include <ext/Errors.hpp>
#include <ext/net/socket_queue.hpp>
#include <ext/net/socket_include.hpp>

#include <ext/library_logger/logger.hpp>
#include <ext/library_logger/logging_macros.hpp>


#define LOG_FATAL(...) EXTLL_FATAL_FMT(m_logger, __VA_ARGS__)
#define LOG_ERROR(...) EXTLL_ERROR_FMT(m_logger, __VA_ARGS__)
#define LOG_WARN(...)  EXTLL_WARN_FMT(m_logger, __VA_ARGS__)
#define LOG_INFO(...)  EXTLL_INFO_FMT(m_logger, __VA_ARGS__)
#define LOG_DEBUG(...) EXTLL_DEBUG_FMT(m_logger, __VA_ARGS__)
#define LOG_TRACE(...) EXTLL_TRACE_FMT(m_logger, __VA_ARGS__)

#if BOOST_OS_WINDOWS

#if _MSC_VER
#pragma warning(disable: 4244)
#endif 

#undef EWOULDBLOCK
#undef EAGAIN
#undef EINTR

#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN      WSAEWOULDBLOCK
#define EINTR       WSAEINTR

#define ioctl ioctlsocket
using ioctl_type = unsigned long;

static int read(socket_handle_type sock, char * buffer, int max_count)
{
	return ::recv(sock, buffer, max_count, 0);
}

#else  // BOOST_OS_POSIX
using ioctl_type = int;

#endif // BOOST_OS_WINDOWS

namespace ext::net
{
	static auto create_interrupt_pair() -> std::tuple<socket_handle_type, socket_handle_type>
	{
#if BOOST_OS_WINDOWS
		auto handle = ::socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (handle < 0) throw_last_socket_error("ext::net::socket_queue: failed to create interrupt UDP socket");

		return std::make_tuple(handle, INVALID_SOCKET);
#else
		int pipefd[2];
		int res = ::pipe(pipefd);
		if (res != 0)
		{
			auto errc = std::error_code(errno, std::system_category());
			throw std::system_error(errc, "ext::net::socket_queue: failed to create interrupt pipe pair");
		}

		return std::make_tuple(pipefd[0], pipefd[1]);
#endif
	}

	void socket_queue::configure(socket_streambuf & sock)
	{
		sock.timeout(m_timeout);
	}

	void socket_queue::interrupt()
	{
		if (not m_interrupted.exchange(true, std::memory_order_release))
		{
#if BOOST_OS_WINDOWS
			int res = close(m_interrupt_listen);
			assert(res == 0); EXT_UNUSED(res);
#else
			char dummy = 0;
			int res = ::write(m_interrupt_write, &dummy, 1);
			//int err = errno;
			assert(res == 1); EXT_UNUSED(res);
#endif // BOOST_OS_WINDOWS
		}
	}

	auto socket_queue::process_interrupted()
	{
		LOG_DEBUG("ext::net::socket_queue interrupted");

#if BOOST_OS_WINDOWS
		std::tie(m_interrupt_listen, m_interrupt_write) = create_interrupt_pair();
#else
		consume_all_input(m_interrupt_listen);
#endif

		m_interrupted.store(false, std::memory_order_relaxed);
		return interrupted;
	}

	void socket_queue::consume_all_input(handle_type sock)
	{
		constexpr ioctl_type buffer_size = 256;
		char buffer[buffer_size];

		ioctl_type avail = 0;
		int res = ::ioctl(sock, FIONREAD, &avail);
		if (res != 0) avail = 0;

		while (avail)
		{
			int res = read(sock, buffer, std::min(buffer_size, avail));
			if (res == -1) throw_last_socket_error("ext::net::socket_queue::consume_all_input: ::read failed");

			avail -= res;
		}
	}

	struct socket_queue::helper
	{
		static auto fill_fdset(fd_set * readset, fd_set * writeset, socket_queue & queue, time_point until) -> std::tuple<handle_type, time_point>
		{
			auto & list = queue.m_socks;
			auto first = list.begin();
			auto last  = list.end();

			duration_type min_timeout = duration_type::max();
			handle_type max_handle = queue.m_interrupt_listen;

			FD_ZERO(readset);
			FD_ZERO(writeset);
			FD_SET(queue.m_interrupt_listen, readset);

			for (auto & listener : queue.m_listeners)
			{
				max_handle = std::max(listener.handle(), max_handle);
				FD_SET(listener.handle(), readset);
			}

			for (; first != last; ++first)
			{
				auto & item = *first;
				auto & sock = item.sock;
				auto handle = sock.handle();

				if (item.wtype & readable)
					FD_SET(handle, readset);

				if (item.wtype & writable)
					FD_SET(handle, writeset);

				auto passed = until - first->submit_time;
				auto timeout = sock.timeout() - passed;
				min_timeout = std::min(timeout, min_timeout);
				max_handle = std::max(max_handle, handle);
			}

			until = time_point::max() - until >= min_timeout // check overflow
			        ? until + min_timeout
			        : time_point::max();

			return std::make_tuple(max_handle, until);
		}
	};

	auto socket_queue::find_ready_socket(sock_list::iterator first, sock_list::iterator last, time_point now) -> sock_list::iterator
	{
		for (; first != last; ++first)
		{
			auto & item = *first;
			auto & sock = item.sock;
			// have some data
			if (sock.in_avail())
			{
				LOG_TRACE("socket {} is readable", sock.handle());
				break;
			}

			// socket timed out
			auto timeout = sock.timeout();
			if (now - item.submit_time >= timeout)
			{
				LOG_INFO("socket {} timed out", sock.handle());
				sock.set_last_error(make_error_code(sock_errc::timeout), "socket_queue");
				break;
			}
		}

		return first;
	}

	auto socket_queue::wait_ready(time_point until) -> wait_status
	{
		int res, err;
		sockoptlen_t solen;
		handle_type max_handle, listener_handle;
		sock_list::iterator first, last, it;

		time_point now, sock_until;
		timeval select_timeout;
		fd_set readset, writeset;

		if (m_interrupted.load(std::memory_order_relaxed))
			goto interrupted;

		if (m_listeners.empty() and m_socks.empty())
			return empty_queue;

    find_ready:
		now = std::chrono::steady_clock::now();
		first = m_socks.begin();
		last  = m_socks.end();

		m_cur = find_ready_socket(it = m_cur, last, now);
		if (m_cur != last) return ready;
		m_cur = find_ready_socket(first, it, now);
		if (m_cur != it)   return ready;

    again:
		if (m_interrupted.load(std::memory_order_relaxed))
			goto interrupted;

		now = std::chrono::steady_clock::now();
		if (now >= until) return timeout;

		std::tie(max_handle, sock_until) = helper::fill_fdset(&readset, &writeset, *this, now);
		make_timeval(std::min(sock_until, until) - now, select_timeout);

		LOG_TRACE("executing select with timeout {} seconds, queue: {}l/{}s", select_timeout.tv_sec, m_listeners.size(), m_socks.size());
		res = ::select(max_handle + 1, &readset, &writeset, nullptr, &select_timeout);
		if (res == 0)
		{
			LOG_TRACE("select timed out, restarting");
			goto find_ready;
		}

		if (res == -1)
		{
			err = last_socket_error();

			// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
			// also select allowed return EAGAIN instead of ENOMEM -> repeat either
			if (err == EAGAIN or err == EWOULDBLOCK or err == EINTR) goto again;

			auto errc = std::error_code(err, std::system_category());
			LOG_ERROR("got error while executing select: {}", ext::FormatError(errc));

			throw std::system_error(errc, "ext::net::socket_queue::wait_ready: ::select failed");
		}

		if (m_interrupted.load(std::memory_order_relaxed) or FD_ISSET(m_interrupt_listen, &readset))
			goto interrupted;

		// check listeners
		for (auto & listener : m_listeners)
		{
			listener_handle = listener.handle();
			if (not FD_ISSET(listener_handle, &readset))
				continue;

			auto new_sock = listener.accept();
			LOG_DEBUG("got new socket {} connection from {}", new_sock.handle(), new_sock.peer_endpoint());

			configure(new_sock);
			submit(std::move(new_sock));
		}

		first = m_socks.begin();
		last  = m_socks.end();

		// check sockets
		for (auto it = first; it != last; ++it)
		{
			auto & item = *it;
			auto & sock = item.sock;
			auto handle = sock.handle();
			bool socket_ready = (item.wtype & readable and FD_ISSET(handle, &readset)) or (item.wtype & writable and FD_ISSET(handle, &writeset));
			if (not socket_ready) continue;

			solen = sizeof(err);
			res = ::getsockopt(handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &solen);
			if (res != 0) goto sockopt_error;
			if (err != 0) goto sock_error;

			LOG_TRACE("socket {} is readable", handle);
			m_cur = it;
			return ready;

        sockopt_error:
			err = last_socket_error();
        sock_error:
			// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
			// that probably should never happen for getsockopt(..., SO_ERROR, ...)
			if (err == EAGAIN or err == EWOULDBLOCK or err == EINTR) continue;

			auto errc = std::error_code(err, std::system_category());
			sock.set_last_error(errc, "socket_queue");

			LOG_INFO("socket {} has error", handle, ext::FormatError(errc));
			m_cur = it;
			return ready;
		}

		// this can happen if select succeeded -> we got new socket from listener, but it's not ready yet
		goto again;

    interrupted:
		return process_interrupted();
	}

	auto socket_queue::wait() const -> wait_status
	{
		return wait_until(std::chrono::steady_clock::time_point::max());
	}

	auto socket_queue::wait_for(duration_type timeout) const -> wait_status
	{
		return wait_until(std::chrono::steady_clock::now() + timeout);
	}

	auto socket_queue::wait_until(time_point until) const -> wait_status
	{
		return ext::unconst(this)->wait_ready(until);
	}

	auto socket_queue::take() -> std::tuple<wait_status, socket_streambuf>
	{
		auto result_status = wait();
		socket_streambuf result;

		if (result_status == ready)
		{
			result = std::move(m_cur->sock);
			m_cur = m_socks.erase(m_cur);

			LOG_TRACE("socket {} taken", result.handle());
		}

		return std::make_tuple(result_status, std::move(result));
	}

	void socket_queue::submit(socket_streambuf buf, wait_type wtype)
	{
		LOG_TRACE("socket {} submitted", buf.handle());
		assert(wtype & readable or wtype & writable);

		m_socks.push_back({
		    std::move(buf),
		    wtype,
		    std::chrono::steady_clock::now(),
		});
	}

	void socket_queue::submit(socket_stream sock, wait_type wtype)
	{
		return submit(std::move(*sock.rdbuf()), wtype);
	}

	void socket_queue::clear() noexcept
	{
		m_listeners.clear();
		m_socks.clear();
	}

	void socket_queue::add_listener(ext::net::listener listener)
	{
		assert(listener.is_listening());
		m_listeners.push_back(std::move(listener));
	}

	auto socket_queue::remove_listener(unsigned short port) -> ext::net::listener
	{
		auto first = m_listeners.begin();
		auto last  = m_listeners.end();

		for (; first != last; ++first)
		{
			auto & listener = *first;
			auto sock_port = listener.sock_port();
			if (sock_port == port)
			{
				auto result = std::move(listener);
				m_listeners.erase(first);
				return result;
			}
		}

		return {};
	}	

	socket_queue::socket_queue()
	{
		std::tie(m_interrupt_listen, m_interrupt_write) = create_interrupt_pair();
	}

	socket_queue::~socket_queue()
	{
		if (m_interrupt_listen != -1) close(m_interrupt_listen);
		if (m_interrupt_write  != -1) close(m_interrupt_write);
	}

	socket_queue::socket_queue(socket_queue && other) noexcept
	    : m_socks(std::move(other.m_socks)),
	      m_listeners(std::move(other.m_listeners)),
	      m_cur(std::exchange(other.m_cur, {})),
	      m_interrupted(other.m_interrupted.exchange(false, std::memory_order_relaxed)),
	      m_interrupt_listen(std::exchange(other.m_interrupt_listen, -1)),
	      m_interrupt_write(std::exchange(other.m_interrupt_write, -1)),
	      m_timeout(std::exchange(other.m_timeout, duration_type::max())),
	      m_logger(std::exchange(other.m_logger, nullptr))
	{

	}

	socket_queue & socket_queue::operator=(socket_queue && other) noexcept
	{
		if (this != &other)
		{
			this->~socket_queue();
			new (this) socket_queue(std::move(other));
		}

		return *this;
	}
}
