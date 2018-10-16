#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <codecvt>
#include <iostream>

#include <ext/netlib/socket_base.hpp>
#include <ext/netlib/socket_include.hpp>

#if BOOST_OS_WINDOWS
#include <ext/codecvt_conv.hpp>
#include <ext/Errors.hpp>
#endif

#ifdef _MSC_VER
// warning C4244: '=' : conversion from '__int64' to 'long', possible loss of data
// warning C4244: 'initializing' : conversion from '__int64' to 'long', possible loss of data
#pragma warning(disable : 4267 4244)
#pragma comment(lib, "ws2_32.lib")

#endif // _MSC_VER

namespace ext::netlib
{
	/************************************************************************/
	/*                platform independent stuff                            */
	/************************************************************************/
	struct socket_condition_category_impl : std::error_category
	{
		virtual const char * name() const noexcept override { return "sock_errc"; }
		virtual std::string message(int val) const override;
		virtual bool equivalent(const std::error_code & code, int cond_val) const noexcept override;
	};

	std::string socket_condition_category_impl::message(int val) const
	{
		switch (static_cast<sock_errc>(val))
		{
		    case sock_errc::eof:       return "end of stream";
		    case sock_errc::timeout:   return "timeout";
		    case sock_errc::regular:   return "regular, not a error";
		    case sock_errc::error:     return "socket error";

		    default: return "unknown sock_errc code";
		}
	}

	bool socket_condition_category_impl::equivalent(const std::error_code & code, int cond_val) const noexcept
	{
		switch (static_cast<sock_errc>(cond_val))
		{
#ifdef EXT_ENABLE_OPENSSL
		    case sock_errc::eof:     return code == openssl_error::zero_return;
#else
		    case sock_errc::eof:     return false;
#endif
		    case sock_errc::regular:
			    return code != sock_errc::error;

		    case sock_errc::error:
			    return code && code != sock_errc::eof;

		    default: return false;
		}
	}


	static socket_condition_category_impl socket_condition_category_impl_instance;

	const std::error_category & socket_condition_category() noexcept
	{
		return socket_condition_category_impl_instance;
	}


	/************************************************************************/
	/*                platform dependent stuff                              */
	/************************************************************************/
#if BOOST_OS_WINDOWS

	int wsastartup(std::uint16_t version)
	{
		WSADATA wsadata;
		auto res = ::WSAStartup(version, &wsadata);
		return res;
	}

	void wsastartup()
	{
		WORD ver = MAKEWORD(2, 2);
		WSADATA wsadata;
		int res = ::WSAStartup(ver, &wsadata);
		if (res == 0) return;

		std::cerr
		    << "Failed to initialize winsock version 2.2 library. "
		    << ext::FormatError(std::error_code(res, std::system_category()))
		    << std::endl;

		std::exit(EXIT_FAILURE);
	}

	void wsacleanup()
	{
		::WSACleanup();
	}

	void socket_stream_init()
	{
		wsastartup();

#ifdef EXT_ENABLE_OPENSSL
		openssl_init();
#endif
	}

	int last_socket_error() noexcept
	{
		return ::WSAGetLastError();
	}

	std::error_code last_socket_error_code() noexcept
	{
		return std::error_code(::WSAGetLastError(), std::system_category());
	}

	BOOST_NORETURN void throw_socket_error(int code, const char * errmsg)
	{
		throw std::system_error(std::error_code(code, std::system_category()), errmsg);
	}

	BOOST_NORETURN void throw_socket_error(int code, const std::string & errmsg)
	{
		throw std::system_error(std::error_code(code, std::system_category()), errmsg);
	}

	BOOST_NORETURN void throw_last_socket_error(const std::string & errmsg)
	{
		throw std::system_error(last_socket_error_code(), errmsg);
	}

	void addrinfo_deleter::operator ()(addrinfo_type * ptr) const
	{
		FreeAddrInfoW(ptr);
	}

	int close(socket_handle_type sock)
	{
		return ::closesocket(sock);
	}

	void inet_ntop(const sockaddr * addr, std::wstring & wstr, unsigned short & port)
	{
		const wchar_t * res;
		DWORD buflen = INET6_ADDRSTRLEN;
		wchar_t buffer[INET6_ADDRSTRLEN];

		if (addr->sa_family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			res = ::InetNtopW(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ::ntohs(addr4->sin_port);
		}
		else if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			res = InetNtopW(AF_INET6, const_cast<in_addr6 *>(&addr6->sin6_addr), buffer, buflen);
			port = ::ntohs(addr6->sin6_port);
		}
		else
		{
			throw std::system_error(
			    std::make_error_code(std::errc::address_family_not_supported),
			    "inet_ntop unsupported address family"
			);
		}

		if (res == nullptr)
			throw_last_socket_error("InetNtopW failed");

		wstr.assign(res);
	}

	void inet_ntop(const sockaddr * addr, std::string & str, unsigned short & port)
	{
		const wchar_t * res;
		DWORD buflen = INET6_ADDRSTRLEN;
		wchar_t buffer[INET6_ADDRSTRLEN];

		if (addr->sa_family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			res = ::InetNtopW(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ::ntohs(addr4->sin_port);
		}
		else if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			res = InetNtopW(AF_INET6, const_cast<in_addr6 *>(&addr6->sin6_addr), buffer, buflen);
			port = ::ntohs(addr6->sin6_port);
		}
		else
		{
			throw std::system_error(
			    std::make_error_code(std::errc::address_family_not_supported),
			    "inet_ntop unsupported address family"
			);
		}

		if (res == nullptr)
			throw_last_socket_error("InetNtopW failed");

		std::codecvt_utf8<wchar_t> cvt;
		auto in = boost::make_iterator_range_n(buffer, std::wcslen(buffer));
		ext::codecvt_convert::to_bytes(cvt, in, str);
	}

	auto inet_ntop(const sockaddr * addr) -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		inet_ntop(addr, res.first, res.second);
		return res;
	}


	bool inet_pton(int family, const wchar_t * waddr, sockaddr * out)
	{
		INT res;
		if (family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<sockaddr_in *>(out);
			res = ::InetPton(family, waddr, &addr4->sin_addr);
		}
		else if (family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<sockaddr_in6 *>(out);
			res = ::InetPton(family, waddr, &addr6->sin6_addr);
		}
		else
		{
			throw_socket_error(WSAEAFNOSUPPORT, "InetPtonW failed");
		}

		if (res == -1) throw_last_socket_error("InetPtonW failed");
		return res > 0;
	}

	bool inet_pton(int family, const std::wstring & waddr, sockaddr * out)
	{
		INT res = InetPton(family, waddr.c_str(), out);
		if (res == -1) throw_last_socket_error("InetPtonW failed");
		return res > 0;
	}

	bool inet_pton(int family, const char * addr, sockaddr * out)
	{
		std::codecvt_utf8<wchar_t> cvt;
		auto in = boost::make_iterator_range_n(addr, std::strlen(addr));
		auto waddr = ext::codecvt_convert::from_bytes(cvt, in);

		return inet_pton(family, waddr.c_str(), out);
	}

	bool inet_pton(int family, const std::string & addr, sockaddr * out)
	{
		std::codecvt_utf8<wchar_t> cvt;
		auto waddr = ext::codecvt_convert::from_bytes(cvt, addr);

		return inet_pton(family, waddr.c_str(), out);
	}

	/************************************************************************/
	/*                   getaddrinfo                                        */
	/************************************************************************/
	addrinfo_ptr getaddrinfo(const wchar_t * host, const wchar_t * service, std::error_code & err)
	{
		addrinfo_type hints;

		::ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_socktype = SOCK_STREAM;

		addrinfo_type * ptr;
		int res = ::GetAddrInfoW(host, service, &hints, &ptr);
		if (res == 0)
		{
			err.clear();
			return addrinfo_ptr(ptr);
		}
		else
		{
			err.assign(res, std::system_category());
			return nullptr;
		}
	}

	addrinfo_ptr getaddrinfo(const wchar_t * host, const wchar_t * service)
	{
		addrinfo_type hints;

		::ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_socktype = SOCK_STREAM;

		addrinfo_type * ptr;
		int res = ::GetAddrInfoW(host, service, &hints, &ptr);
		if (res == 0)
			return addrinfo_ptr(ptr);
		else
			throw_socket_error(res, "GetAddrInfoW failed");
	}

	addrinfo_ptr getaddrinfo(const char * host, const char * service, std::error_code & err)
	{
		std::codecvt_utf8<wchar_t> cvt;

		std::wstring whoststr, wservicestr;

		const wchar_t * whost = nullptr;
		const wchar_t * wservice = nullptr;

		if (host)
		{
			auto in = boost::make_iterator_range_n(host, std::strlen(host));
			ext::codecvt_convert::from_bytes(cvt, in, whoststr);
			whost = whoststr.c_str();
		}

		if (service)
		{
			auto in = boost::make_iterator_range_n(service, std::strlen(service));
			ext::codecvt_convert::from_bytes(cvt, in, wservicestr);
			wservice = wservicestr.c_str();
		}

		return getaddrinfo(whost, wservicestr, err);
	}

	addrinfo_ptr getaddrinfo(const char * host, const char * service)
	{
		std::codecvt_utf8<wchar_t> cvt;

		std::wstring whoststr, wservicestr;

		const wchar_t * whost = nullptr;
		const wchar_t * wservice = nullptr;

		if (host)
		{
			auto in = boost::make_iterator_range_n(host, std::strlen(host));
			ext::codecvt_convert::from_bytes(cvt, in, whoststr);
			whost = whoststr.c_str();
		}

		if (service)
		{
			auto in = boost::make_iterator_range_n(service, std::strlen(service));
			ext::codecvt_convert::from_bytes(cvt, in, wservicestr);
			wservice = wservicestr.c_str();
		}

		return getaddrinfo(whost, wservicestr);
	}

#else

	/************************************************************************/
	/*                auxiliary functions                                   */
	/************************************************************************/
	void socket_stream_init()
	{
#ifdef EXT_ENABLE_OPENSSL
		openssl_init();
#endif
	}

	struct gai_error_category_impl : public std::error_category
	{
		const char * name() const noexcept override  { return "gai"; }
		std::string message(int code) const override { return ::gai_strerror(code); }
	};

	const gai_error_category_impl gai_error_category_instance;

	const std::error_category & gai_error_category()
	{
		return gai_error_category_instance;
	}

	int last_socket_error() noexcept
	{
		return errno;
	}

	std::error_code last_socket_error_code() noexcept
	{
		return std::error_code(errno, std::generic_category());
	}

	BOOST_NORETURN void throw_socket_error(int code, const char * errmsg)
	{
		throw std::system_error(std::error_code(code, std::generic_category()), errmsg);
	}

	BOOST_NORETURN void throw_socket_error(int code, const std::string & errmsg)
	{
		throw std::system_error(std::error_code(code, std::generic_category()), errmsg);
	}

	BOOST_NORETURN void throw_last_socket_error(const std::string & errmsg)
	{
		throw std::system_error(last_socket_error_code(), errmsg);
	}

	void set_port(addrinfo_type * addr, unsigned short port)
	{
		static_assert(offsetof(sockaddr_in, sin_port) == offsetof(sockaddr_in6, sin6_port), "sin_port/sin6_port offset differs");
		for (; addr; addr = addr->ai_next)
			reinterpret_cast<sockaddr_in *>(addr->ai_addr)->sin_port = htons(port);
	}

	auto get_port(addrinfo_type * addr) -> unsigned short
	{
		// both sockaddr_in6 and sockaddr_in have port member on same offset
		unsigned short port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
		return ntohs(port);
	}

	void make_timeval(std::chrono::steady_clock::duration val, timeval & tv)
	{
		long micro = std::chrono::duration_cast<std::chrono::microseconds>(val).count();
		if (micro < 0) micro = 0;

		tv.tv_sec  = micro / 1000000;
		tv.tv_usec = micro % 1000000;
	}

	void inet_ntop(const sockaddr * addr, std::string & str, unsigned short & port)
	{
		// on HPUX libc(not libxnet) somehow sa_family is not set in ::getpeername/::getsockname
		const int force_afinet = BOOST_OS_HPUX;

		const char * res;
		const socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[buflen];

		if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			res = ::inet_ntop(AF_INET6, const_cast<in6_addr *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
		}
		else if (addr->sa_family == AF_INET || force_afinet)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			res = ::inet_ntop(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ntohs(addr4->sin_port);
		}
		else
		{
			throw std::system_error(
			    std::make_error_code(std::errc::address_family_not_supported),
			    "inet_ntop unsupported address family"
			);
		}

		if (res == nullptr)
			throw_last_socket_error("inet_ntop failed");

		str = res;
	}

	auto inet_ntop(const sockaddr * addr) -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		inet_ntop(addr, res.first, res.second);
		return res;
	}

	bool inet_pton(int family, const char * addr, sockaddr * out)
	{
		int res;
		if (family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<sockaddr_in *>(out);
			res = ::inet_pton(family, addr, &addr4->sin_addr);
		}
		else if (family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<sockaddr_in6 *>(out);
			res = ::inet_pton(family, addr, &addr6->sin6_addr);
		}
		else
		{
			throw std::system_error(
			    std::make_error_code(std::errc::address_family_not_supported),
			    "inet_pton unsupported address family"
			);
		}

		if (res == -1) throw_last_socket_error("inet_pton failed");
		return res > 0;
	}

	bool inet_pton(int family, const std::string & addr, sockaddr * out)
	{
		return inet_pton(family, addr.c_str(), out);
	}

	void addrinfo_deleter::operator ()(addrinfo_type * ptr) const
	{
		::freeaddrinfo(ptr);
	}

	int close(socket_handle_type sock)
	{
		return ::close(sock);
	}

	addrinfo_ptr getaddrinfo(const char * host, const char * service)
	{
		std::error_code err;
		auto result = getaddrinfo(host, service, err);
		if (result) return result;

		throw std::system_error(err, "getaddrinfo failed");
	}

	addrinfo_ptr getaddrinfo(const char * host, const char * service, std::error_code & err)
	{
		addrinfo_type hints;

		std::memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_socktype = SOCK_STREAM;

		addrinfo_type * ptr;
		int res = ::getaddrinfo(host, service, &hints, &ptr);
		if (res == 0)
		{
			err.clear();
			return addrinfo_ptr(ptr);
		}

		if (res == EAI_SYSTEM)
		{
			err.assign(errno, std::generic_category());
			return addrinfo_ptr(nullptr);
		}
		else
		{
			err.assign(res, gai_error_category());
			return addrinfo_ptr(nullptr);
		}
	}

#endif // #if BOOST_OS_WINDOWS
} // namespace ext
