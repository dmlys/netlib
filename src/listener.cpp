#include <cstring>      // for std::memset and stuff
#include <memory>

#include <ext/itoa.hpp>
#include <ext/netlib/socket_base.hpp>
#include <ext/netlib/socket_include.hpp>
#include <ext/netlib/listener.hpp>

namespace ext::netlib
{
	bool listener::is_listening() const
	{
		if (not m_listening_socket) return false;

		int enabled = 0;
		socklen_t len = sizeof(enabled);
		int res = ::getsockopt(m_listening_socket, SOL_SOCKET, SO_ACCEPTCONN, reinterpret_cast<char *>(&enabled), &len);
		if (res != 0) throw_last_socket_error("ext::netlib::listener::is_listening: ::getsockopt SO_ACCEPTCONN failed");

		return enabled;
	}

	void listener::getsockname(sockaddr_type * addr, socklen_t * addrlen)
	{
		if (m_listening_socket == -1)
			throw std::runtime_error("ext::netlib::listener::getsockname: bad socket");

		sockoptlen_t * so_addrlen = reinterpret_cast<sockoptlen_t *>(addrlen);
		auto res = ::getsockname(m_listening_socket, addr, so_addrlen);
		if (res != 0) throw_last_socket_error("ext::netlib::listener::getsockname: ::getsockname failed");
	}

	std::string listener::sock_endpoint()
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		std::string host;
		unsigned short port;
		inet_ntop(addr, host, port);

		ext::itoa_buffer<unsigned short> buffer;
		host += ':';
		host += ext::itoa(port, buffer);

		return host;
	}

	unsigned short listener::sock_port()
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		// both sockaddr_in6 and sockaddr_in have port member on same offset
		auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
		return ntohs(port);
	}

	void listener::sock_name(std::string & name, unsigned short & port)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		inet_ntop(addr, name, port);
	}

	auto listener::sock_name() -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		sock_name(res.first, res.second);
		return res;
	}

	std::string listener::sock_address()
	{
		std::string addr; unsigned short port;
		sock_name(addr, port);
		return addr;
	}

	void listener::bind(std::string ipaddr, unsigned short port)
	{
		addrinfo hint, *addrres;

		ext::itoa_buffer<unsigned short> service_buffer;
		auto * service = ext::itoa(port, service_buffer);
		auto * host = ipaddr.empty() ? nullptr : ipaddr.c_str();

		std::memset(&hint, 0, sizeof(hint));
		hint.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG | AI_ALL;
		hint.ai_family = AF_UNSPEC;
		hint.ai_protocol = IPPROTO_TCP;
		hint.ai_socktype = SOCK_STREAM;

		int res;
        do res = ::getaddrinfo(host, service, &hint, &addrres); while (res == EAI_AGAIN);
		if (res != 0) throw_last_socket_error("ext::netlib::listener::bind: ::getaddrinfo failed");

		m_listening_socket = ::socket(addrres->ai_family, addrres->ai_socktype, addrres->ai_protocol);
		if (m_listening_socket == -1) throw_last_socket_error("ext::netlib::listener::bind: ::socket failed");

		//int enabled = 0;
		//res = ::setsockopt(m_listening_socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&enabled), sizeof(enabled));
		//if (res != 0) throw_last_socket_error("::setsockopt IPV6_V6ONLY failed");

		int enabled = 1;
		res = ::setsockopt(m_listening_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&enabled), sizeof(enabled));
		if (res != 0) throw_last_socket_error("ext::netlib::listener::bind: ::setsockopt SO_REUSEADDR failed");

		res = ::bind(m_listening_socket, addrres->ai_addr, addrres->ai_addrlen);
		if (res != 0) throw_last_socket_error("ext::netlib::listener::bind: ::bind failed");

		freeaddrinfo(addrres);
	}

	void listener::listen(int backlog /* = 1 */)
	{
		int res = ::listen(m_listening_socket, backlog);
		if (res < 0) throw_last_socket_error("ext::netlib::listener::listen: ::listen failed");
	}

	socket_streambuf listener::accept()
	{
		socket_handle_type sock = ::accept(m_listening_socket, nullptr, nullptr);
		if (sock == -1) throw_last_socket_error("ext::netlib::listener::accept: ::accept failed");

		return socket_streambuf(sock);
	}

	void listener::shutdown()
	{
		if (m_listening_socket == -1) return;

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
		if (m_listening_socket == -1) return;

		int res = ext::netlib::close(m_listening_socket);
		m_listening_socket = -1;
		assert(res == 0);
	}

	listener::listener(listener && l) noexcept
	    : m_listening_socket(std::exchange(l.m_listening_socket, -1))
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
		if (m_listening_socket == -1) return;

		int res = ext::netlib::close(m_listening_socket);
		assert(res == 0);
	}
}
