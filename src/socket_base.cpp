#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <algorithm>

#include <ext/itoa.hpp>
#include <ext/net/socket_base.hpp>
#include <ext/net/socket_include.hpp>

#include <boost/scope_exit.hpp>

#if BOOST_OS_WINDOWS
#include <codecvt> // for std::codecvt_utf8<wchar_t>
#include <ext/codecvt_conv.hpp>
#include <ext/errors.hpp>
#endif

#ifdef _MSC_VER
// warning C4244: '=' : conversion from '__int64' to 'long', possible loss of data
// warning C4244: 'initializing' : conversion from '__int64' to 'long', possible loss of data
#pragma warning(disable : 4267 4244)
#pragma comment(lib, "ws2_32.lib")

#endif // _MSC_VER

namespace ext::net
{
	const int af_unspec = AF_UNSPEC;
	const int af_inet   = AF_INET;
	const int af_inet6  = AF_INET6;
	
	const int sock_stream = SOCK_STREAM;
	const int sock_dgram  = SOCK_DGRAM;
	const int sock_seqpacket = SOCK_SEQPACKET;
	
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
			case sock_errc::eof:         return "end of stream";
			case sock_errc::would_block: return "would block";
			case sock_errc::timeout:     return "timeout";
			case sock_errc::ssl_error:   return "ssl error";
			case sock_errc::regular:     return "regular, not a error";
			case sock_errc::error:       return "socket error";

			default: return "unknown sock_errc code";
		}
	}

	bool socket_condition_category_impl::equivalent(const std::error_code & code, int cond_val) const noexcept
	{
		switch (static_cast<sock_errc>(cond_val))
		{
#ifdef EXT_ENABLE_OPENSSL
			case sock_errc::eof:          return code == openssl_error::zero_return;
			case sock_errc::ssl_error:    return code != openssl_error::zero_return and (code.category() == openssl::openssl_err_category() or code.category() == openssl::openssl_ssl_category());
#else
			case sock_errc::eof:          return false;
			case sock_errc::ssl_error:    return false;
#endif

			case sock_errc::would_block:
#if BOOST_OS_WINDOWS
				if (code.category() == std::system_category() and code.value() == WSAEWOULDBLOCK)
					return true;
#else
				if (code.category() == std::generic_category() and (code.value() == EWOULDBLOCK or code.value() == EAGAIN))
				    return true;
#endif
#ifdef EXT_ENABLE_OPENSSL
				if (code.category() == openssl::openssl_ssl_category() and (code.value() == SSL_ERROR_WANT_READ or code.value() == SSL_ERROR_WANT_READ))
					return true;
#endif
				return false;

			case sock_errc::regular:      return code != sock_errc::error;
			case sock_errc::error:        return code && code != sock_errc::eof && code != sock_errc::would_block;

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
		    << ext::format_error(std::error_code(res, std::system_category()))
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

	void socket_stream_cleanup()
	{
#ifdef EXT_ENABLE_OPENSSL
		openssl_cleanup();
#endif

		wsacleanup();
	}
	
	int last_socket_error() noexcept
	{
		return ::WSAGetLastError();
	}

	const std::error_category & socket_error_category() noexcept
	{
		return std::system_category();
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

	BOOST_NORETURN void throw_last_socket_error(const char * errmsg)
	{
		throw std::system_error(last_socket_error_code(), errmsg);
	}

	std::error_code socket_rw_error(int res, int last_error)
	{
		// it was eof
		if (res >= 0)
			return make_error_code(sock_errc::eof);;

		if (last_error == WSAEINTR) return make_error_code(std::errc::interrupted);

		if (last_error == WSAEWOULDBLOCK)
			return make_error_code(sock_errc::would_block);

		return std::error_code(last_error, std::system_category());
	}

#ifdef EXT_ENABLE_OPENSSL
	std::error_code socket_ssl_rw_error(int res, SSL * ssl)
	{
		int err, ssl_err;
		std::error_code errc;
		ssl_err = ::SSL_get_error(ssl, res);
		switch (ssl_err)
		{
			// can this happen? just try to handle as SSL_ERROR_SYSCALL
			// according to doc, this can happen if res > 0
			case SSL_ERROR_NONE:

			case SSL_ERROR_SSL:
			case SSL_ERROR_SYSCALL:
				// if it some generic SSL error
				if ((err = ::ERR_peek_error()))
				{
					errc.assign(err, openssl_err_category());
					break;
				}

				if ((err = ::WSAGetLastError()))
				{
					if (err == WSAEINTR)
					{
						errc = std::make_error_code(std::errc::interrupted);
						break;
					}

					// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
					// also select allowed return EAGAIN instead of ENOMEM -> repeat either
					// NOTE: this should not happen, SSL_ERROR_WANT_{READ/WRITE} should shadow this case
					if (err == WSAEWOULDBLOCK)
					{
						errc = make_error_code(sock_errc::would_block);
						break;
					}

					errc.assign(err, std::system_category());
					break;
				}

				// it was unexpected eof
				if (ssl_err == 0)
				{
					errc = make_error_code(sock_errc::eof);
					break;
				}

				[[fallthrough]];

			// if it's SSL_ERROR_WANT_{WRITE,READ}
			// last error can be WSAEINTR or WSAEWOULDBLOCK - repeat operation
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:

			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_WANT_X509_LOOKUP:
			case SSL_ERROR_WANT_CONNECT:
			case SSL_ERROR_WANT_ACCEPT:
			default:
			    errc.assign(ssl_err, openssl_ssl_category());
				break;
		}

		return errc;
	}
#endif

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
		using rep_type = std::chrono::microseconds::duration::rep;
		using result_type = decltype(tv.tv_sec);
		using tv_limits = std::numeric_limits<result_type>;

		rep_type micro = std::chrono::duration_cast<std::chrono::microseconds>(val).count();
		if (micro < 0) micro = 0;

		tv.tv_sec  = std::min<std::common_type_t<rep_type, result_type>>(micro / 1000000, tv_limits::max());
		tv.tv_usec = std::min<std::common_type_t<rep_type, result_type>>(micro % 1000000, tv_limits::max());
	}

	int poll_mktimeout(std::chrono::steady_clock::duration val)
	{
		using rep_type = std::chrono::milliseconds::duration::rep;
		using int_limits = std::numeric_limits<int>;

		rep_type milli = std::chrono::duration_cast<std::chrono::milliseconds>(val).count();
		if (milli < 0) return 0;

		return std::min<std::common_type_t<rep_type, int>>(milli, int_limits::max());
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

	std::string make_addr_error_description(int err)
	{
		ext::itoa_buffer<int> buffer;
		std::string errstr;
		errstr.reserve(32);

		errstr += '<';

		switch (err)
		{
			case WSAEFAULT:         errstr += "WSAEFAULT"; break;
			case WSAEINVAL:         errstr += "WSAEINVAL"; break;
			case WSAENOBUFS:        errstr += "WSAENOBUFS"; break;
			case WSANOTINITIALISED: errstr += "WSANOTINITIALISED"; break;
			case WSAEINPROGRESS:    errstr += "WSAEINPROGRESS"; break;
			case WSAENOTCONN:       errstr += "WSAENOTCONN"; break;
			case WSAENOTSOCK:       errstr += "WSAENOTSOCK"; break;
			case WSAENETDOWN:       errstr += "WSAENETDOWN"; break;
			default:                errstr += "unknown"; break;
		}

		errstr += ':';
		errstr += ext::itoa(err, buffer);
		errstr += '>';

		return errstr;
	}

	std::string sock_addr(sockaddr * addr)
	{
		unsigned short port;
		const char * host_ptr;
		const socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[buflen];
		std::string host;

		if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			host_ptr = ::inet_ntop(AF_INET6, const_cast<in6_addr *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
			if (not host_ptr) throw_last_socket_error("inet_ntop failed");

			host += '[';
			host += host_ptr;
			host += ']';
		}
		else if (addr->sa_family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			host_ptr = ::inet_ntop(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ntohs(addr4->sin_port);
			if (not host_ptr) throw_last_socket_error("inet_ntop failed");

			host = host_ptr;
		}
		else
		{
			throw std::system_error(
			    std::make_error_code(std::errc::address_family_not_supported),
			    "inet_ntop unsupported address family"
			);
		}

		ext::itoa_buffer<unsigned short> port_buffer;
		host += ':';
		host += ext::itoa(port, port_buffer);

		return host;
	}

	std::string sock_addr_noexcept(sockaddr * addr)
	{
		unsigned short port;
		const char * host_ptr;
		const socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[buflen];
		std::string host;

		if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			host_ptr = ::inet_ntop(AF_INET6, const_cast<in6_addr *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
			if (not host_ptr) return make_addr_error_description(::WSAGetLastError());

			host += '[';
			host += host_ptr;
			host += ']';
		}
		else if (addr->sa_family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			host_ptr = ::inet_ntop(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ntohs(addr4->sin_port);
			if (not host_ptr) return make_addr_error_description(::WSAGetLastError());

			host = host_ptr;
		}
		else
		{
			return make_addr_error_description(WSAEAFNOSUPPORT);
		}

		ext::itoa_buffer<unsigned short> port_buffer;
		host += ':';
		host += ext::itoa(port, port_buffer);

		return host;
	}

	unsigned short sock_port(sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
			return ::ntohs(port);
		}
		
		throw std::system_error(
		    std::make_error_code(std::errc::address_family_not_supported),
		    "sock_port unsupported address family"
		);
	}
	
	unsigned short sock_port_noexcept(sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
			return ::ntohs(port);
		}
		
		return 0;
	}

	void addrinfo_deleter::operator ()(addrinfo_type * ptr) const
	{
		FreeAddrInfoW(ptr);
	}

	int close(socket_handle_type sock)
	{
		return ::closesocket(sock);
	}

	/************************************************************************/
	/*                   getaddrinfo                                        */
	/************************************************************************/
	addrinfo_ptr getaddrinfo(const wchar_t * host, const wchar_t * service, const addrinfo_type * hints, std::error_code & err)
	{
		addrinfo_type * ptr;
		int res = ::GetAddrInfoW(host, service, hints, &ptr);
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
	
	addrinfo_ptr getaddrinfo(const wchar_t * host, const wchar_t * service, const addrinfo_type * hints)
	{
		addrinfo_type * ptr;
		int res = ::GetAddrInfoW(host, service, hints, &ptr);
		if (res == 0)
			return addrinfo_ptr(ptr);
		else
			throw_socket_error(res, "GetAddrInfoW failed");
	}
	
	addrinfo_ptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints, std::error_code & err)
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

		return getaddrinfo(whost, wservice, hints, err);
	}

	addrinfo_ptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints)
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

		return getaddrinfo(whost, wservice, hints);
	}

	void socketpair(socket_handle_type fds[2], int address_family, int sock_type, int sock_proto)
	{
		return manual_socketpair(fds, address_family, sock_type, sock_proto);
	}
	
	bool socketpair(socket_handle_type fds[2], std::error_code & err, int address_family, int sock_type, int sock_proto)
	{
		return manual_socketpair(fds, err, address_family, sock_type, sock_proto);
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
	
	void socket_stream_cleanup()
	{
#ifdef EXT_ENABLE_OPENSSL
		openssl_cleanup();
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

	const std::error_category & socket_error_category() noexcept
	{
		return std::generic_category();
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

	BOOST_NORETURN void throw_last_socket_error(const char * errmsg)
	{
		throw std::system_error(last_socket_error_code(), errmsg);
	}

	std::error_code socket_rw_error(int res, int last_error)
	{
		// it was eof
		if (res >= 0)
			return make_error_code(sock_errc::eof);;

		if (last_error == EINTR) return make_error_code(std::errc::interrupted);

		// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
		// also select allowed return EAGAIN instead of ENOMEM -> repeat either
		if (last_error == EAGAIN or last_error == EWOULDBLOCK)
			return make_error_code(sock_errc::would_block);

		return std::error_code(last_error, std::generic_category());
	}

#ifdef EXT_ENABLE_OPENSSL
	std::error_code socket_ssl_rw_error(int res, SSL * ssl)
	{
		int err, ssl_err;
		std::error_code errc;
		ssl_err = ::SSL_get_error(ssl, res);
		switch (ssl_err)
		{
			// can this happen? just try to handle as SSL_ERROR_SYSCALL
			// according to doc, this can happen if res > 0
			case SSL_ERROR_NONE:

			case SSL_ERROR_SSL:
			case SSL_ERROR_SYSCALL:
				// if it some generic SSL error
				if ((err = ::ERR_peek_error()))
				{
					errc.assign(err, openssl_err_category());
					break;
				}

				if ((err = errno))
				{
					if (err == EINTR)
					{
						errc = std::make_error_code(std::errc::interrupted);
						break;
					}

					// when using nonblocking socket, EAGAIN/EWOULDBLOCK mean repeat operation later,
					// also select allowed return EAGAIN instead of ENOMEM -> repeat either
					// NOTE: this should not happen, SSL_ERROR_WANT_{READ/WRITE} should shadow this case
					if (err == EAGAIN or err == EWOULDBLOCK)
					{
						errc = make_error_code(sock_errc::would_block);
						break;
					}

					errc.assign(err, std::generic_category());
					break;
				}

				// it was unexpected eof
				if (ssl_err == 0)
				{
					errc = make_error_code(sock_errc::eof);
					break;
				}

				[[fallthrough]];

			// if it's SSL_ERROR_WANT_{WRITE,READ}
			// errno can be EAGAIN or EINTR - repeat operation
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:

			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_WANT_X509_LOOKUP:
			case SSL_ERROR_WANT_CONNECT:
			case SSL_ERROR_WANT_ACCEPT:
			default:
			    errc.assign(ssl_err, openssl_ssl_category());
				break;
		}

		return errc;
	}
#endif

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
		using rep_type = std::chrono::microseconds::duration::rep;
		using result_type = decltype(tv.tv_sec);
		using tv_limits = std::numeric_limits<result_type>;

		rep_type micro = std::chrono::duration_cast<std::chrono::microseconds>(val).count();
		if (micro < 0) micro = 0;

		tv.tv_sec  = std::min<std::common_type_t<rep_type, result_type>>(micro / 1000000, tv_limits::max());
		tv.tv_usec = std::min<std::common_type_t<rep_type, result_type>>(micro % 1000000, tv_limits::max());
	}

	int poll_mktimeout(std::chrono::steady_clock::duration val)
	{
		using rep_type = std::chrono::milliseconds::duration::rep;
		using int_limits = std::numeric_limits<int>;

		rep_type milli = std::chrono::duration_cast<std::chrono::milliseconds>(val).count();
		if (milli < 0) return 0;

		return std::min<std::common_type_t<rep_type, int>>(milli, int_limits::max());
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

	std::string make_addr_error_description(int err)
	{
		ext::itoa_buffer<int> buffer;
		std::string errstr;
		errstr.reserve(32);

		errstr += '<';

		switch (err)
		{
			case EBADF:        errstr += "EBADF"; break;
			case EINVAL:       errstr += "EINVAL"; break;
			case EFAULT:       errstr += "EFAULT"; break;
			case ENOTCONN:     errstr += "ENOTCONN"; break;
			case ENOTSOCK:     errstr += "ENOTSOCK"; break;
			case EOPNOTSUPP:   errstr += "EOPNOTSUPP"; break;
			case ENOBUFS:      errstr += "ENOBUFS"; break;
			case EAFNOSUPPORT: errstr += "EAFNOSUPPORT"; break;
			case ENOSPC:       errstr += "ENOSPC"; break;
			default:           errstr += "unknown"; break;
		}

		errstr += ':';
		errstr += ext::itoa(err, buffer);
		errstr += '>';

		return errstr;
	}

	std::string sock_addr(sockaddr * addr)
	{
		// on HPUX libc(not libxnet) somehow sa_family is not set in ::getpeername/::getsockname
		const int force_afinet = BOOST_OS_HPUX;

		unsigned short port;
		const char * host_ptr;
		const socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[buflen];
		std::string host;

		if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			host_ptr = ::inet_ntop(AF_INET6, const_cast<in6_addr *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
			if (not host_ptr) throw_last_socket_error("inet_ntop failed");

			host += '[';
			host += host_ptr;
			host += ']';
		}
		else if (addr->sa_family == AF_INET || force_afinet)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			host_ptr = ::inet_ntop(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ntohs(addr4->sin_port);
			if (not host_ptr) throw_last_socket_error("inet_ntop failed");

			host = host_ptr;
		}
		else
		{
			throw std::system_error(
			    std::make_error_code(std::errc::address_family_not_supported),
			    "inet_ntop unsupported address family"
			);
		}

		ext::itoa_buffer<unsigned short> port_buffer;
		host += ':';
		host += ext::itoa(port, port_buffer);

		return host;
	}

	std::string sock_addr_noexcept(sockaddr * addr)
	{
		// on HPUX libc(not libxnet) somehow sa_family is not set in ::getpeername/::getsockname
		const int force_afinet = BOOST_OS_HPUX;

		unsigned short port;
		const char * host_ptr;
		const socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[buflen];
		std::string host;

		if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			host_ptr = ::inet_ntop(AF_INET6, const_cast<in6_addr *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
			if (not host_ptr) return make_addr_error_description(errno);

			host += '[';
			host += host_ptr;
			host += ']';
		}
		else if (addr->sa_family == AF_INET || force_afinet)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			host_ptr = ::inet_ntop(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ntohs(addr4->sin_port);
			if (not host_ptr) return make_addr_error_description(errno);

			host = host_ptr;
		}
		else
		{
			return make_addr_error_description(EAFNOSUPPORT);
		}

		ext::itoa_buffer<unsigned short> port_buffer;
		host += ':';
		host += ext::itoa(port, port_buffer);

		return host;
	}

	unsigned short sock_port(sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
			return ::ntohs(port);
		}
		
		throw std::system_error(
		    std::make_error_code(std::errc::address_family_not_supported),
		    "sock_port unsupported address family"
		);
	}
	
	unsigned short sock_port_noexcept(sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
			return ::ntohs(port);
		}
		
		return 0;
	}

	void addrinfo_deleter::operator ()(addrinfo_type * ptr) const
	{
		::freeaddrinfo(ptr);
	}

	int close(socket_handle_type sock)
	{
		return ::close(sock);
	}
	
	addrinfo_ptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints)
	{
		std::error_code err;
		auto result = getaddrinfo(host, service, hints, err);
		if (result) return result;

		throw std::system_error(err, "getaddrinfo failed");
	}

	addrinfo_ptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints, std::error_code & err)
	{
		addrinfo_type * ptr;
		int res = ::getaddrinfo(host, service, hints, &ptr);
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
	
	void socketpair(socket_handle_type fds[2], int address_family, int sock_type, int sock_proto)
	{
		int res = ::socketpair(address_family, sock_type, sock_proto, fds);
		if (res != 0) throw_last_socket_error("socketpair failed");
	}
	
	bool socketpair(socket_handle_type fds[2], std::error_code & err, int address_family, int sock_type, int sock_proto)
	{
		int res = ::socketpair(address_family, sock_type, sock_proto, fds);
		if (res == 0) return true;
		
		err = last_socket_error_code();
		return false;
	}
	
#endif // #if BOOST_OS_WINDOWS


	/************************************************************************/
	/*                platform independent stuff                            */
	/************************************************************************/
	addrinfo_ptr loopback_addr(int address_family, int sock_type, int sock_proto)
	{
		std::error_code err;
		auto result = loopback_addr(err, address_family, sock_type, sock_proto);
		if (result) return result;
		
		throw std::system_error(err, "loopback_addr failed");
	}
	
	addrinfo_ptr loopback_addr(std::error_code & err, int address_family, int sock_type, int sock_proto)
	{
		// AI_ADDRCONFIG - Use configuration of this host to choose returned address type..
		//   If hints.ai_flags includes the AI_ADDRCONFIG flag, then IPv4 addresses are returned in the list pointed to by res only
		//   if the local system has at least one IPv4 address configured, and IPv6 addresses are returned only if the local system has at least one IPv6 address configured.
		//   The loopback address is not considered for this case as valid as a configured address.
		//   This flag is useful on, for example, IPv4-only systems, to ensure that getaddrinfo() does not return IPv6 socket addresses that would always fail in connect(2) or bind(2).
		// AI_ALL - Return IPv4 mapped and IPv6 addresses.
		//   If hints.ai_flags specifies the AI_V4MAPPED flag, and hints.ai_family was specified as AF_INET6, and no matching IPv6 addresses could be found,
		///  then return IPv4-mapped IPv6 addresses in the list pointed to by res.
		///  If both AI_V4MAPPED and AI_ALL are specified in hints.ai_flags, then return both IPv6 and IPv4-mapped IPv6 addresses in the list pointed to by res.
		///  AI_ALL is ignored if AI_V4MAPPED is not also specified.
		addrinfo_type hints;
		std::memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_ADDRCONFIG | AI_ALL /*| AI_NUMERICHOST | AI_NUMERICSERV*/;
		hints.ai_family = address_family;
		hints.ai_socktype = sock_type;
		hints.ai_protocol = sock_proto;
		
		return getaddrinfo(nullptr, "0", &hints, err);
	}

	void manual_socketpair(socket_handle_type fds[2], int address_family, int sock_type, int sock_proto)
	{
		socket_handle_type listen_sock = invalid_socket, sock1 = invalid_socket, sock2 = invalid_socket;
		auto addr_info = loopback_addr(address_family, sock_type, sock_proto);
		
		BOOST_SCOPE_EXIT_ALL(&listen_sock, &sock1, &sock2)
		{
			if (listen_sock != invalid_socket) close(listen_sock);
			if (sock1       != invalid_socket) close(sock1);
			if (sock2       != invalid_socket) close(sock2);
		};
		
		listen_sock = ::socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
		if (listen_sock == invalid_socket) throw_last_socket_error("ext::net::manual_socketpair: failed to create listen socket");
		
		sock1 = ::socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
		if (sock1 == invalid_socket) throw_last_socket_error("ext::net::manual_socketpair: failed to create socket");
		
		int res;
		//res = ::fcntl(sock1, F_SETFL, ::fcntl(sock1, F_GETFL, 0) | O_NONBLOCK);
		//if (res != 0) throw_last_socket_error("ext::net::manual_socketpair: sock1 ::fcntl nonblocking failed");
		
		assert(sock_port(addr_info->ai_addr) == 0);
		res = ::bind(listen_sock, addr_info->ai_addr, addr_info->ai_addrlen);
		if (res != 0) throw_last_socket_error("ext::net::manual_socketpair: ::bind failed");

		sockaddr_storage sockstore;
		auto * addrptr = reinterpret_cast<sockaddr *>(&sockstore);
		socklen_t addrlen = sizeof(sockstore);
		
		res = ::getsockname(listen_sock, addrptr, &addrlen);
		if (res != 0) throw_last_socket_error("ext::net::manual_socketpair: ::getsockname failed");
		
		res = ::listen(listen_sock, 1);
		if (res < 0) throw_last_socket_error("ext::net::manual_socketpair: ::listen failed");
		
		res = ::connect(sock1, addrptr, addrlen);
		if (res != 0) throw_last_socket_error("ext::net::manual_socketpair: ::connect failed");
		
		sock2 = ::accept(listen_sock, nullptr, nullptr);
		if (sock2 == invalid_socket) throw_last_socket_error("ext::net::manual_socketpair: ::accept failed");
		
		//res = ::fcntl(sock1, F_SETFL, ::fcntl(sock1, F_GETFL, 0) | O_NONBLOCK);
		//if (res != 0) throw_last_socket_error("ext::net::manual_socketpair: sock2 ::fcntl nonblocking failed");
		
		close(listen_sock);
		
		fds[0] = sock1;
		fds[1] = sock2;
		
		sock1 = sock2 = listen_sock = invalid_socket;
	}
	
	bool manual_socketpair(socket_handle_type fds[2], std::error_code & err, int address_family, int sock_type, int sock_proto)
	{
		int res;
		
		sockaddr_storage sockstore;
		auto * addrptr = reinterpret_cast<sockaddr *>(&sockstore);
		socklen_t addrlen = sizeof(sockstore);
		
		socket_handle_type listen_sock = invalid_socket, sock1 = invalid_socket, sock2 = invalid_socket;
		auto addr_info = loopback_addr(address_family, sock_type, sock_proto);
		
		listen_sock = ::socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
		if (listen_sock == invalid_socket) goto error;
		
		sock1 = ::socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
		if (sock1 == invalid_socket) goto error;
		
		//res = ::fcntl(sock1, F_SETFL, ::fcntl(sock1, F_GETFL, 0) | O_NONBLOCK);
		//if (res != 0) throw_last_socket_error("ext::net::manual_socketpair: sock1 ::fcntl nonblocking failed");
		
		assert(sock_port(addr_info->ai_addr) == 0);
		res = ::bind(listen_sock, addr_info->ai_addr, addr_info->ai_addrlen);
		if (res != 0) goto error;
		
		res = ::getsockname(listen_sock, addrptr, &addrlen);
		if (res != 0) goto error;
		
		res = ::listen(listen_sock, 1);
		if (res < 0)  goto error;
		
		res = ::connect(sock1, addrptr, addrlen);
		if (res != 0) goto error;
		
		sock2 = ::accept(listen_sock, nullptr, nullptr);
		if (sock2 == invalid_socket) goto error;
		
		//res = ::fcntl(sock1, F_SETFL, ::fcntl(sock1, F_GETFL, 0) | O_NONBLOCK);
		//if (res != 0) throw_last_socket_error("ext::net::manual_socketpair: sock2 ::fcntl nonblocking failed");
		
		close(listen_sock);
		
		fds[0] = sock1;
		fds[1] = sock2;
		
		return true;
		
	error:
		err = last_socket_error_code();
		
		if (listen_sock != invalid_socket) close(listen_sock);
		if (sock1       != invalid_socket) close(sock1);
		if (sock2       != invalid_socket) close(sock2);
		
		return false;
	}
	
} // namespace ext
