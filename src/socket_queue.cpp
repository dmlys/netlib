#include <cstring>      // for std::memset and stuff
#include <memory>

#include <fmt/format.h>

#include <ext/config.hpp>
#include <ext/utility.hpp>
#include <ext/errors.hpp>
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
#pragma warning(disable: 4244) // C4244 'argument' : conversion from 'type1' to 'type2', possible loss of data
#endif 

#undef EWOULDBLOCK
#undef EAGAIN
#undef EINTR

#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN      WSAEWOULDBLOCK
#define EINTR       WSAEINTR

#define ioctl ioctlsocket
#define poll  WSAPoll
using ioctl_type = unsigned long;

inline static int read(socket_handle_type sock, char * buffer, int max_count)
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
		if (handle == invalid_socket) throw_last_socket_error("ext::net::socket_queue: failed to create interrupt UDP socket");

		return std::make_tuple(handle, invalid_socket);
#else
		int pipefd[2];
		int res = ::pipe(pipefd);
		if (res != 0)
		{
			auto errc = std::error_code(errno, std::generic_category());
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

	auto socket_queue::find_ready_socket(sock_list::iterator first, sock_list::iterator last) -> sock_list::iterator
	{
		for (; first != last; ++first)
			if (first->ready) return first;

		return first;
	}

	struct socket_queue::helper
	{
		static auto fill_fdset(socket_queue & queue, time_point until, fd_set * readset, fd_set * writeset) -> std::tuple<handle_type, time_point>
		{
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

			for (auto & item : queue.m_socks)
			{
				auto & sock = item.sock;
				auto handle = sock.handle();

				if (item.wtype & readable)
					FD_SET(handle, readset);

				if (item.wtype & writable)
					FD_SET(handle, writeset);

				auto passed = until - item.submit_time;
				auto timeout = sock.timeout() - passed;
				min_timeout = std::min(timeout, min_timeout);
				max_handle = std::max(max_handle, handle);
			}

			until = time_point::max() - until >= min_timeout // check overflow
			        ? until + min_timeout
			        : time_point::max();

			return std::make_tuple(max_handle, until);
		}

		static void calculate_socket_state(socket_queue & queue, time_point now, fd_set * readset, fd_set * writeset)
		{
			auto * m_logger = queue.m_logger;
			for (auto & item : queue.m_socks)
			{
				auto sock_handle = item.sock.handle();
				unsigned wait_type = 0;
				if (item.wtype & writable and FD_ISSET(sock_handle, writeset))
					wait_type |= writable, item.ready = 1, item.ready_status = ready;
				if (item.wtype & readable and FD_ISSET(sock_handle, readset))
					wait_type |= readable, item.ready = 1, item.ready_status = ready;

				if (not item.ready)
				{
					// socket timed out
					if (now - item.submit_time >= item.sock.timeout())
					{
						LOG_INFO("socket {} timed out", sock_handle);
						item.sock.set_last_error(make_error_code(sock_errc::timeout), "socket_queue");
					}
				}
				else
				{
					int res, err;
					sockoptlen_t solen;
					solen = sizeof(err);
					res = ::getsockopt(sock_handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &solen);
					if (res != 0) goto sockopt_error;
					if (err != 0) goto sock_error;

					const char * ready_str;
					switch (static_cast<socket_queue::wait_type>(wait_type))
					{
						case readable: ready_str = "readable"; break;
						case writable: ready_str = "writable"; break;
						case both:     ready_str = "readable and writable"; break;
						default: EXT_UNREACHABLE();
					}

					LOG_TRACE("socket {} is {}", sock_handle, ready_str);
					continue;

				sockopt_error:
					err = last_socket_error();
				sock_error:
					// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
					// that probably should never happen for getsockopt(..., SO_ERROR, ...)
					if (err == EAGAIN or err == EWOULDBLOCK or err == EINTR) continue;

					auto errc = std::error_code(err, socket_error_category());
					item.sock.set_last_error(errc, "socket_queue");

					LOG_INFO("socket {} has error", sock_handle, ext::format_error(errc));
					continue;
				}
			}
		}

#if EXT_NET_USE_POLL
		static auto fill_pollfds(socket_queue & queue, time_point until, std::vector<pollfd> & poll_array) -> std::tuple<time_point, pollfd *, pollfd *, pollfd *, pollfd *>
		{
			duration_type min_timeout = duration_type::max();
			poll_array.resize(1 + queue.m_listeners.size() + queue.m_socks.size());
			auto * cur_fd = poll_array.data();
			cur_fd->fd = queue.m_interrupt_listen;
			cur_fd->events = POLLIN;

			for (auto & listener : queue.m_listeners)
			{
				++cur_fd;
				cur_fd->fd = listener.handle();
				cur_fd->events = POLLIN;
			}

			for (auto & item : queue.m_socks)
			{
				++cur_fd;
				auto & sock = item.sock;
				auto handle = sock.handle();
				cur_fd->fd = handle;
				cur_fd->events = 0;
				if (item.wtype & readable)
					cur_fd->events |= POLLIN;
				if (item.wtype & writable)
					cur_fd->events |= POLLOUT;

				auto passed = until - item.submit_time;
				auto timeout = sock.timeout() - passed;
				min_timeout = std::min(timeout, min_timeout);
			}

			until = time_point::max() - until >= min_timeout // check overflow
			        ? until + min_timeout
			        : time_point::max();

			auto first = poll_array.data();
			auto socks_first = first + 1 + queue.m_listeners.size();
			auto last = first + poll_array.size();
			return std::make_tuple(until, first + 1, socks_first, socks_first, last);
		}

		static void calculate_socket_state(socket_queue & queue, time_point now, const pollfd * pfirst, const pollfd * plast)
		{
			auto * m_logger = queue.m_logger;
			auto first = queue.m_socks.begin();

			for (; pfirst != plast; ++first, ++pfirst)
			{
				const pollfd & pfd = *pfirst;
				auto & item = *first;
				auto sock_handle = item.sock.handle();
				assert(sock_handle == pfd.fd);

				unsigned wait_type = 0;

				if (pfd.revents & POLLERR)
				{
					int res, err;
					sockoptlen_t solen;
					solen = sizeof(err);
					res = ::getsockopt(sock_handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&err), &solen);
					if (res != 0) goto sockopt_error;
					if (err != 0) goto sock_error;

					item.ready_status = ready;
					item.ready = 1;

					if (pfd.events & POLLHUP)
					{
						item.sock.set_last_error(make_error_code(sock_errc::eof), "socket_queue");
						LOG_INFO("socket {} was diconnected or aborted(POLHUP + POLLERR without err)", sock_handle);
					}
					else
					{
						item.sock.set_last_error(make_error_code(sock_errc::error), "socket_queue");
						LOG_INFO("socket {} has unknown error(POLLERR with getsockopt SO_ERROR == 0, without POLLHUP)", sock_handle);
					}
					
					continue;

				sockopt_error:
					err = last_socket_error();
				sock_error:
					// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
					// that probably should never happen for getsockopt(..., SO_ERROR, ...)
					if (err == EAGAIN or err == EWOULDBLOCK or err == EINTR) continue;

					item.ready_status = ready;
					item.ready = 1;

					auto errc = std::error_code(err, socket_error_category());
					item.sock.set_last_error(errc, "socket_queue");

					LOG_INFO("socket {} has error", sock_handle);
					continue;
				}

				if (pfd.revents & POLLIN)
					wait_type |= readable, item.ready = 1, item.ready_status = ready;
				if (pfd.revents & POLLOUT)
					wait_type |= writable, item.ready = 1, item.ready_status = ready;
				if (pfd.revents & POLLHUP)
					item.ready = 1, item.ready_status = ready;

				if (not item.ready)
				{
					// socket timed out
					if (now - item.submit_time >= item.sock.timeout())
					{
						LOG_INFO("socket {} timed out", sock_handle);
						item.sock.set_last_error(make_error_code(sock_errc::timeout), "socket_queue");
						item.ready = 1, item.ready_status = ready;
					}
				}
				else
				{
					const char * ready_str;
					//switch (static_cast<socket_queue::wait_type>(wait_type))
					switch (wait_type)
					{
						case 0       : ready_str = "disconnected(POLLHUP)";  break;
						case readable: ready_str = "readable(POLLIN)"; break;
						case writable: ready_str = "writable(POLLOUT)"; break;
						case both:     ready_str = "readable(POLLIN) and writable(POLLOUT)"; break;
						default: EXT_UNREACHABLE();
					}

					LOG_TRACE("socket {} is {}", sock_handle, ready_str);
					continue;
				}
			}
		}

#endif // EXT_NET_USE_POLL
	};

	auto socket_queue::wait_ready(time_point until) -> wait_status
	{
		int res, err;
		sock_list::iterator socks_first, socks_last, socks_it;
		time_point now, sock_until;

#if EXT_NET_USE_POLL
		std::vector<pollfd> pollfds;
		pollfd * plfirst, * pllast, * psfirst, * pslast;
		int poll_timeout;
#else
		handle_type max_handle, listener_handle;
		fd_set readset, writeset;
		timeval select_timeout;
#endif

		if (m_interrupted.load(std::memory_order_relaxed))
			goto interrupted;

		if (m_listeners.empty() and m_socks.empty())
			return empty_queue;

	restart:
		socks_first = m_socks.begin();
		socks_last  = m_socks.end();

		m_cur = find_ready_socket(socks_it = m_cur, socks_last);
		if (m_cur != socks_last) return static_cast<wait_status>(m_cur->ready_status);
		m_cur = find_ready_socket(socks_first, socks_it);
		if (m_cur != socks_it)   return static_cast<wait_status>(m_cur->ready_status);

	again:
		if (m_interrupted.load(std::memory_order_relaxed))
			goto interrupted;

		now = time_point::clock::now();
		if (now >= until) return timeout;

#if EXT_NET_USE_POLL
		std::tie(sock_until, plfirst, pllast, psfirst, pslast) = helper::fill_pollfds(*this, now, pollfds);
		poll_timeout = poll_mktimeout(std::min(sock_until, until) - now);

		LOG_TRACE("executing poll with timeout {} seconds, queue: {}l/{}s", poll_timeout / 1000, m_listeners.size(), m_socks.size());
		res = ::poll(pollfds.data(), pollfds.size(), poll_timeout);
		if (res == 0)
		{
			LOG_TRACE("poll timed out, restarting");
			helper::calculate_socket_state(*this, now = time_point::clock::now(), psfirst, pslast);
			goto restart;
		}

		if (res == -1)
		{
			err = last_socket_error();

			// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
			// also poll allowed return EAGAIN instead of ENOMEM -> repeat either
			if (err == EAGAIN or err == EWOULDBLOCK or err == EINTR) goto again;

			auto errc = std::error_code(err, socket_error_category());
			LOG_ERROR("got error while executing poll: {}", ext::format_error(errc));

			throw std::system_error(errc, "ext::net::socket_queue::wait_ready: ::poll failed");
		}

		if (m_interrupted.load(std::memory_order_relaxed) or pollfds[0].revents & POLLIN)
			goto interrupted;

#else // EXT_NET_USE_POLL
		std::tie(max_handle, sock_until) = helper::fill_fdset(*this, now, &readset, &writeset);
		make_timeval(std::min(sock_until, until) - now, select_timeout);

		LOG_TRACE("executing select with timeout {} seconds, queue: {}l/{}s", select_timeout.tv_sec, m_listeners.size(), m_socks.size());
		res = ::select(max_handle + 1, &readset, &writeset, nullptr, &select_timeout);
		if (res == 0)
		{
			LOG_TRACE("select timed out, restarting");
			helper::calculate_socket_state(*this, now = time_point::clock::now(), &readset, &writeset);
			goto restart;
		}

		if (res == -1)
		{
			err = last_socket_error();

			// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
			// also select allowed return EAGAIN instead of ENOMEM -> repeat either
			if (err == EAGAIN or err == EWOULDBLOCK or err == EINTR) goto again;

			auto errc = std::error_code(err, socket_error_category());
			LOG_ERROR("got error while executing select: {}", ext::format_error(errc));

			throw std::system_error(errc, "ext::net::socket_queue::wait_ready: ::select failed");
		}

		if (m_interrupted.load(std::memory_order_relaxed) or FD_ISSET(m_interrupt_listen, &readset))
			goto interrupted;

#endif // EXT_NET_USE_POLL
		// check listeners
		for (auto & listener : m_listeners)
		{
#if EXT_NET_USE_POLL
			bool pending = plfirst->revents & POLLIN; ++plfirst;
			if (not pending) continue;
#else
			listener_handle = listener.handle();
			if (not FD_ISSET(listener_handle, &readset)) continue;
#endif
			auto new_sock = listener.accept();
			LOG_DEBUG("got new socket {} connection from {}", new_sock.handle(), new_sock.peer_endpoint());

			configure(new_sock);
			submit(std::move(new_sock));
		}

		// calculate state of sockets, ready, timeout, errors... transfer into internal queue
#if EXT_NET_USE_POLL
		helper::calculate_socket_state(*this, now = time_point::clock::now(), psfirst, pslast); goto restart;
#else
		helper::calculate_socket_state(*this, now = time_point::clock::now(), &readset, &writeset); goto restart;
#endif

	interrupted:
		return process_interrupted();
	}

	auto socket_queue::wait() const -> wait_status
	{
		return wait_until(time_point::max());
	}

	auto socket_queue::wait_for(duration_type timeout) const -> wait_status
	{
		return wait_until(time_point::clock::now() + timeout);
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

	static bool socket_streambuf_have_pending_data(socket_streambuf & buf)
	{
		auto first = buf.gptr();
		auto last  = buf.egptr();
		bool pending = first != last;

#ifdef EXT_ENABLE_OPENSSL
		if (buf.ssl_handle())
			pending |= ::SSL_has_pending(buf.ssl_handle());
#endif

		return pending;
	}

	void socket_queue::submit(socket_streambuf buf, wait_type wtype)
	{
		LOG_TRACE("socket {} submitted", buf.handle());
		assert(wtype & readable or wtype & writable);

		unsigned ready = 0;
		unsigned ready_status = ready;

		if (wtype & readable)
			ready = socket_streambuf_have_pending_data(buf);

		m_socks.push_back({
			std::move(buf),
			time_point::clock::now(),
			wtype,
			ready, ready_status
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

	auto socket_queue::take_sockets() -> std::vector<socket_streambuf>
	{
		std::vector<socket_streambuf> result;
		for (auto & item : m_socks)
			result.push_back(std::move(item.sock));
		m_socks.clear();

		return result;
	}


	socket_queue::socket_queue()
	{
		std::tie(m_interrupt_listen, m_interrupt_write) = create_interrupt_pair();
	}

	socket_queue::~socket_queue()
	{
		if (m_interrupt_listen != invalid_socket) close(m_interrupt_listen);
		if (m_interrupt_write  != invalid_socket) close(m_interrupt_write);
	}

	socket_queue::socket_queue(socket_queue && other) noexcept
	    : m_socks(std::move(other.m_socks)),
	      m_listeners(std::move(other.m_listeners)),
	      m_cur(std::exchange(other.m_cur, {})),
	      m_interrupted(other.m_interrupted.exchange(false, std::memory_order_relaxed)),
	      m_interrupt_listen(std::exchange(other.m_interrupt_listen, invalid_socket)),
	      m_interrupt_write(std::exchange(other.m_interrupt_write, invalid_socket)),
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
