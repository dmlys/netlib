#include <cstring>      // for std::memset and stuff
#include <memory>

#include <ext/config.hpp>
#include <ext/itoa.hpp>
#include <ext/net/socket_base.hpp>
#include <ext/net/socket_include.hpp>
#include <ext/net/listener.hpp>


namespace ext::net
{
	listener_exception::listener_exception(std::string sock_endpoint, std::error_code errc, std::string msg)
	    : std::system_error(errc, std::move(msg) + ", sock_endpoint = " + sock_endpoint), m_sock_endpoint(std::move(sock_endpoint))
	{

	}

	EXT_NORETURN static void throw_last_listener_error(std::string sock_endpoint, const char * errmsg)
	{
		throw listener_exception(std::move(sock_endpoint), last_socket_error_code(), errmsg);
	}

	bool listener::is_listening(socket_handle_type handle)
	{
		if (handle == invalid_socket) return false;

		int enabled = 0;
		socklen_t len = sizeof(enabled);
		int res = ::getsockopt(handle, SOL_SOCKET, SO_ACCEPTCONN, reinterpret_cast<char *>(&enabled), &len);
		if (res != 0) throw_last_socket_error("ext::net::listener::is_listening: ::getsockopt SO_ACCEPTCONN failed");

		return enabled;
	}

	bool listener::is_socket(socket_handle_type handle)
	{
		return handle != invalid_socket;
	}


	void listener::bind(socket_handle_type & handle, const char * ipaddr, unsigned short port, int af)
	{
		addrinfo_type hints;

		ext::itoa_buffer<unsigned short> service_buffer;
		auto * service = ext::itoa(port, service_buffer);
		auto * host = ipaddr;

		// AI_PASSIVE - Socket address is intended for `bind'.
		// AI_ADDRCONFIG - Use configuration of this host to choose returned address type..
		//   If hints.ai_flags includes the AI_ADDRCONFIG flag, then IPv4 addresses are returned in the list pointed to by res only
		//   if the local system has at least one IPv4 address configured, and IPv6 addresses are returned only if the local system has at least one IPv6 address configured.
		//   The loopback address is not considered for this case as valid as a configured address.
		//   This flag is useful on, for example, IPv4-only systems, to ensure that getaddrinfo() does not return IPv6 socket addresses that would always fail in connect(2) or bind(2).
		// AI_V4MAPPED - IPv4 mapped addresses are acceptable.
		// AI_ALL - Return IPv4 mapped and IPv6 addresses.
		//   If hints.ai_flags specifies the AI_V4MAPPED flag, and hints.ai_family was specified as AF_INET6, and no matching IPv6 addresses could be found,
		///  then return IPv4-mapped IPv6 addresses in the list pointed to by res.
		///  If both AI_V4MAPPED and AI_ALL are specified in hints.ai_flags, then return both IPv6 and IPv4-mapped IPv6 addresses in the list pointed to by res.
		///  AI_ALL is ignored if AI_V4MAPPED is not also specified.
		std::memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_V4MAPPED | AI_ALL;
		hints.ai_family = af;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_socktype = SOCK_STREAM;

		std::error_code err;
		addrinfo_uptr addrinfo = ext::net::getaddrinfo(host, service, &hints, err);
		if (err) throw std::system_error(err, "ext::net::listener::bind: ::getaddrinfo failed");

		bind(handle, addrinfo->ai_addr, addrinfo->ai_addrlen, addrinfo->ai_socktype, addrinfo->ai_protocol);
	}
	
	void listener::bind(socket_handle_type & handle, sockaddr * sockaddr, socklen_t addrlen, int socktype, int protocol/* = 0 */)
	{
		auto shandle = ::socket(sockaddr->sa_family, socktype, protocol);
		if (shandle == invalid_socket) throw_last_socket_error("ext::net::listener::bind: ::socket failed");

		socket_uhandle suhandle(shandle);

		int res, enabled = 1;
		res = ::setsockopt(shandle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&enabled), sizeof(enabled));
		if (res != 0) throw_last_socket_error("ext::net::listener::bind: ::setsockopt SO_REUSEADDR failed");

		std::string sock_endpoint = sock_addr_noexcept(sockaddr);
		res = ::bind(shandle, sockaddr, addrlen);
		if (res != 0) throw_last_listener_error(sock_endpoint, "ext::net::listener::bind: ::bind failed");
		
		handle = suhandle.release();
	}

	void listener::listen(socket_handle_type handle, int backlog)
	{
		auto endpoint = ext::net::sock_endpoint(handle);
		int res = ::listen(handle, backlog);
		if (res < 0) throw_last_listener_error(endpoint, "ext::net::listener::listen: ::listen failed");
	}

	socket_handle_type listener::accept(socket_handle_type handle)
	{
		socket_handle_type sock = ::accept(handle, nullptr, nullptr);
		if (sock == invalid_socket) throw_last_socket_error("ext::net::listener::accept: ::accept failed");
		
		return sock;
	}
	
	void listener::shutdown(socket_handle_type handle)
	{
		if (handle == invalid_socket) return;

#if BOOST_OS_WINDOWS
		constexpr int how = SD_BOTH;
#else
		constexpr int how = SHUT_RDWR;
#endif

		int res = ::shutdown(handle, how);
		if (res != 0) throw_last_socket_error("shutdown failed");
	}

	void listener::close() noexcept
	{
		if (m_listening_socket == invalid_socket) return;

		int res = ext::net::close(m_listening_socket);
		m_listening_socket = invalid_socket;
		assert(res == 0); EXT_UNUSED(res);
	}

	listener::listener(listener && l) noexcept
	    : m_listening_socket(std::exchange(l.m_listening_socket, invalid_socket))
	{

	}

	listener & listener::operator=(listener && l) noexcept
	{
		if (this != &l)
		{
			this->~listener();
			new (this) listener(std::move(l));
		}

		return *this;
	}

	void swap(listener & l1, listener & l2) noexcept
	{
		std::swap(l1.m_listening_socket, l2.m_listening_socket);
	}

	listener::~listener()
	{
		if (m_listening_socket == invalid_socket) return;

		int res = ext::net::close(m_listening_socket);
		assert(res == 0); EXT_UNUSED(res);
	}
}
