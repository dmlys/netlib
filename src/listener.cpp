﻿#include <cstring>      // for std::memset and stuff
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

	bool listener::is_listening() const
	{
		if (not m_listening_socket) return false;

		int enabled = 0;
		socklen_t len = sizeof(enabled);
		int res = ::getsockopt(m_listening_socket, SOL_SOCKET, SO_ACCEPTCONN, reinterpret_cast<char *>(&enabled), &len);
		if (res != 0) throw_last_socket_error("ext::net::listener::is_listening: ::getsockopt SO_ACCEPTCONN failed");

		return enabled;
	}

	bool listener::is_socket() const
	{
		return m_listening_socket != invalid_socket;
	}

	void listener::getsockname(sockaddr_type * addr, socklen_t * addrlen) const
	{
		if (m_listening_socket == invalid_socket)
			throw std::runtime_error("ext::net::listener::getsockname: bad socket");

		sockoptlen_t * so_addrlen = reinterpret_cast<sockoptlen_t *>(addrlen);
		auto res = ::getsockname(m_listening_socket, addr, so_addrlen);
		if (res != 0) throw_last_socket_error("ext::net::listener::getsockname: ::getsockname failed");
	}

	std::string listener::sock_endpoint() const
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		return sock_addr(addr);
	}

	unsigned short listener::sock_port() const
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		// both sockaddr_in6 and sockaddr_in have port member on same offset
		auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
		return ntohs(port);
	}

	void listener::sock_name(std::string & name, unsigned short & port) const
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		inet_ntop(addr, name, port);
	}

	auto listener::sock_name() const -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		sock_name(res.first, res.second);
		return res;
	}

	std::string listener::sock_address() const
	{
		std::string addr; unsigned short port;
		sock_name(addr, port);
		return addr;
	}

	void listener::bind(std::string ipaddr, unsigned short port, int af)
	{
		addrinfo_type hints;

		ext::itoa_buffer<unsigned short> service_buffer;
		auto * service = ext::itoa(port, service_buffer);
		auto * host = ipaddr.empty() ? nullptr : ipaddr.c_str();

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
		addrinfo_ptr addrinfo = getaddrinfo(host, service, &hints, err);
		if (err) throw std::system_error(err, "ext::net::listener::bind: ::getaddrinfo failed");

		bind(addrinfo->ai_addr, addrinfo->ai_addrlen, addrinfo->ai_socktype, addrinfo->ai_protocol);
	}
	
	void listener::bind(sockaddr * sockaddr, socklen_t addrlen, int socktype, int protocol/* = 0 */)
	{
		m_listening_socket = ::socket(sockaddr->sa_family, socktype, protocol);
		if (m_listening_socket == invalid_socket) throw_last_socket_error("ext::net::listener::bind: ::socket failed");

		//int enabled = 0;
		//res = ::setsockopt(m_listening_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&enabled), sizeof(enabled));
		//if (res != 0) throw_last_socket_error("::setsockopt IPV6_V6ONLY failed");

		int res, enabled = 1;
		res = ::setsockopt(m_listening_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&enabled), sizeof(enabled));
		if (res != 0) throw_last_socket_error("ext::net::listener::bind: ::setsockopt SO_REUSEADDR failed");

		std::string sock_endpoint = sock_addr_noexcept(sockaddr);
		res = ::bind(m_listening_socket, sockaddr, addrlen);
		if (res != 0) throw_last_listener_error(sock_endpoint, "ext::net::listener::bind: ::bind failed");
	}

	void listener::listen(int backlog)
	{
		auto endpoint = sock_endpoint();
		int res = ::listen(m_listening_socket, backlog);
		if (res < 0) throw_last_listener_error(endpoint, "ext::net::listener::listen: ::listen failed");
	}

	socket_streambuf listener::accept()
	{
		socket_handle_type sock = accept_handle();
		return socket_streambuf(sock);
	}

	socket_handle_type listener::accept_handle()
	{
		socket_handle_type sock = ::accept(m_listening_socket, nullptr, nullptr);
		if (sock == invalid_socket) throw_last_socket_error("ext::net::listener::accept: ::accept failed");
		
		return sock;
	}
	
	void listener::shutdown()
	{
		if (m_listening_socket == invalid_socket) return;

#if BOOST_OS_WINDOWS
		constexpr int how = SD_BOTH;
#else
		constexpr int how = SHUT_RDWR;
#endif

		int res = ::shutdown(m_listening_socket, how);
		if (res != 0) throw_last_socket_error("shutdown failed");
		//assert(res == 0);
	}

	void listener::close()
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
