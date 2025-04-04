﻿#include <cstdint>
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
#include <ext/errors.hpp>
#include <ext/codecvt_conv/wchar_cvt.hpp>
namespace wchar_cvt = ext::codecvt_convert::wchar_cvt;
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
	
#ifdef MSG_NOSIGNAL
	const int msg_nosignal = MSG_NOSIGNAL;
#else
	const int msg_nosignal = 0;
#endif
	
#ifdef MSG_DONTWAIT
	const int msg_dontwait = MSG_DONTWAIT;
#else
	const int msg_dontwait = 0;
#endif
	
#if BOOST_OS_WINDOWS
	const int shut_rd   = SD_RECEIVE;
	const int shut_wr   = SD_SEND;
	const int shut_rdwr = SD_BOTH;
#else
	const int shut_rd   = SHUT_RD;
	const int shut_wr   = SHUT_WR;
	const int shut_rdwr = SHUT_RDWR;
#endif
	
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
			case sock_errc::eof:          return code == openssl_errc::zero_return;
			case sock_errc::ssl_error:    return code != openssl_errc::zero_return and (code.category() == openssl::openssl_err_category() or code.category() == openssl::openssl_ssl_category());
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

	
	auto add_timeout(std::chrono::steady_clock::time_point tp, std::chrono::steady_clock::duration timeout) -> std::chrono::steady_clock::time_point
	{
		assert(tp.time_since_epoch().count() >= 0);
		assert(timeout >= std::chrono::steady_clock::duration::zero());
		
		// auto result = tp + timeout;
		// if (result >= tp) return result;
		// // overflow happened
		// return std::chrono::steady_clock::time_point::max();
		
		if (tp > std::chrono::steady_clock::time_point::max() - timeout) // overflow
			return std::chrono::steady_clock::time_point::max();
		
		return tp + timeout;
	}
	
	auto add_timeout(std::chrono::steady_clock::duration dur, std::chrono::steady_clock::duration timeout) -> std::chrono::steady_clock::duration
	{
		assert(dur.count() >= 0);
		assert(timeout >= std::chrono::steady_clock::duration::zero());
		
		// auto result = dur + timeout;
		// if (result >= dur) return result;
		// // overflow happened
		// return std::chrono::steady_clock::duration::max();
		
		if (dur > std::chrono::steady_clock::duration::max() - timeout) // overflow
			return std::chrono::steady_clock::duration::max();
		
		return dur + timeout;
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

	void init_socket_library()
	{
		wsastartup();

#ifdef EXT_ENABLE_OPENSSL
		ext::openssl::ssl_init();
#endif
	}

	void free_socket_library()
	{
#ifdef EXT_ENABLE_OPENSSL
		ext::openssl::lib_cleanup();
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

	void inet_ntop(const  in_addr * addr, std::string & str)
	{
		const wchar_t * res;
		DWORD buflen = INET_ADDRSTRLEN;
		wchar_t buffer[INET_ADDRSTRLEN];
		res = InetNtopW(AF_INET, addr, buffer, buflen);
		
		if (res == nullptr)
			throw_last_socket_error("InetNtopW failed");
		
		wchar_cvt::to_utf8(buffer, std::wcslen(buffer), str);
	}
	
	auto inet_ntop(const  in_addr * addr) -> std::string
	{
		std::string str;
		inet_ntop(addr, str);
		return str;
	}
	
	void inet_ntop(const in6_addr * addr, std::string & str)
	{
		const wchar_t * res;
		DWORD buflen = INET6_ADDRSTRLEN;
		wchar_t buffer[INET6_ADDRSTRLEN];
		res = InetNtopW(AF_INET6, addr, buffer, buflen);
		
		if (res == nullptr)
			throw_last_socket_error("InetNtopW failed");
		
		wchar_cvt::to_utf8(buffer, std::wcslen(buffer), str);
	}
	
	auto inet_ntop(const in6_addr * addr) -> std::string
	{
		std::string str;
		inet_ntop(addr, str);
		return str;
	}
	
	void inet_ntop(const in_addr * addr, std::wstring & wstr)
	{
		const wchar_t * res;
		DWORD buflen = INET_ADDRSTRLEN;
		wchar_t buffer[INET_ADDRSTRLEN];
		res = InetNtopW(AF_INET, addr, buffer, buflen);
		
		if (res == nullptr)
			throw_last_socket_error("InetNtopW failed");
		
		wstr.assign(res);
	}
	
	void inet_ntop(const in6_addr * addr, std::wstring & wstr)
	{
		const wchar_t * res;
		DWORD buflen = INET6_ADDRSTRLEN;
		wchar_t buffer[INET6_ADDRSTRLEN];
		res = InetNtopW(AF_INET6, addr, buffer, buflen);
		
		if (res == nullptr)
			throw_last_socket_error("InetNtopW failed");
		
		wstr.assign(res);
	}
	
	void inet_ntop(const sockaddr * addr, std::wstring & wstr, unsigned short & port)
	{
		const wchar_t * res;
		DWORD buflen = INET6_ADDRSTRLEN;
		wchar_t buffer[INET6_ADDRSTRLEN];

		if (addr->sa_family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			res = InetNtopW(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ntohs(addr4->sin_port);
		}
		else if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			res = InetNtopW(AF_INET6, const_cast<in_addr6 *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
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
			res = InetNtopW(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
			port = ntohs(addr4->sin_port);
		}
		else if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			res = InetNtopW(AF_INET6, const_cast<in_addr6 *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
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

		wchar_cvt::to_utf8(buffer, std::wcslen(buffer), str);
	}

	auto inet_ntop(const sockaddr * addr) -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		inet_ntop(addr, res.first, res.second);
		return res;
	}

	bool inet_pton(const char * addr, in_addr * out)
	{
		auto in = boost::make_iterator_range_n(addr, std::strlen(addr));
		auto waddr = wchar_cvt::to_wchar(in);
		
		return inet_pton(waddr.c_str(), out);
	}
	
	bool inet_pton(const std::string & addr, in_addr * out)
	{
		auto waddr = wchar_cvt::to_wchar(addr);
		return inet_pton(waddr, out);
	}
	
	bool inet_pton(const char * addr, in6_addr * out)
	{
		auto in = boost::make_iterator_range_n(addr, std::strlen(addr));
		auto waddr = wchar_cvt::to_wchar(in);
		
		return inet_pton(waddr.c_str(), out);
	}
	
	bool inet_pton(const std::string & addr, in6_addr * out)
	{
		auto waddr = wchar_cvt::to_wchar(addr);
		return inet_pton(waddr, out);
	}
	
	bool inet_pton(const wchar_t * addr, in_addr * out)
	{
		INT res = InetPtonW(AF_INET, addr, out);
		if (res == -1)
			throw_last_socket_error("InetPtonW failed");
		return res > 0;
	}
	
	bool inet_pton(const std::wstring & addr, in_addr * out)
	{
		INT res = InetPtonW(AF_INET, addr.c_str(), out);
		if (res == -1)
			throw_last_socket_error("InetPtonW failed");
		return res > 0;
	}
	
	bool inet_pton(const wchar_t * addr, in6_addr * out)
	{
		INT res = InetPtonW(AF_INET6, addr, out);
		if (res == -1)
			throw_last_socket_error("InetPtonW failed");
		return res > 0;
	}
	
	bool inet_pton(const std::wstring & addr, in6_addr * out)
	{
		INT res = InetPtonW(AF_INET6, addr.c_str(), out);
		if (res == -1)
			throw_last_socket_error("InetPtonW failed");
		return res > 0;
	}
	
	bool inet_pton(int family, const wchar_t * waddr, sockaddr * out)
	{
		INT res;
		if (family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<sockaddr_in *>(out);
			res = InetPtonW(family, waddr, &addr4->sin_addr);
		}
		else if (family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<sockaddr_in6 *>(out);
			res = InetPtonW(family, waddr, &addr6->sin6_addr);
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
		INT res = InetPtonW(family, waddr.c_str(), out);
		if (res == -1) throw_last_socket_error("InetPtonW failed");
		return res > 0;
	}

	bool inet_pton(int family, const char * addr, sockaddr * out)
	{
		auto in = boost::make_iterator_range_n(addr, std::strlen(addr));
		auto waddr = wchar_cvt::to_wchar(in);

		return inet_pton(family, waddr.c_str(), out);
	}

	bool inet_pton(int family, const std::string & addr, sockaddr * out)
	{
		auto waddr = wchar_cvt::to_wchar(addr);
		return inet_pton(family, waddr.c_str(), out);
	}

	void setsock_nonblocking(socket_handle_type sock, bool nonblocking)
	{
		unsigned long enabled = 1;
		int res = ::ioctlsocket(sock, FIONBIO, &enabled);
		if (res != 0) throw_last_socket_error("ext::net::setsock_nonblocking failed");
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

	std::string sockaddr_endpoint(const sockaddr * addr)
	{
		unsigned short port;
		const char * host_ptr;
		const socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[buflen];
		std::string host;

		if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			host_ptr = inet_ntop(AF_INET6, const_cast<in6_addr *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
			if (not host_ptr) throw_last_socket_error("inet_ntop failed");

			host += '[';
			host += host_ptr;
			host += ']';
		}
		else if (addr->sa_family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			host_ptr = inet_ntop(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
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

	std::string sockaddr_endpoint_noexcept(const sockaddr * addr)
	{
		unsigned short port;
		const char * host_ptr;
		const socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[buflen];
		std::string host;

		if (addr->sa_family == AF_INET6)
		{
			auto * addr6 = reinterpret_cast<const sockaddr_in6 *>(addr);
			host_ptr = inet_ntop(AF_INET6, const_cast<in6_addr *>(&addr6->sin6_addr), buffer, buflen);
			port = ntohs(addr6->sin6_port);
			if (not host_ptr) return make_addr_error_description(::WSAGetLastError());

			host += '[';
			host += host_ptr;
			host += ']';
		}
		else if (addr->sa_family == AF_INET)
		{
			auto * addr4 = reinterpret_cast<const sockaddr_in *>(addr);
			host_ptr = inet_ntop(AF_INET, const_cast<in_addr *>(&addr4->sin_addr), buffer, buflen);
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

	unsigned short sockaddr_port(const sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<const sockaddr_in6 *>(addr)->sin6_port;
			return ntohs(port);
		}
		
		throw std::system_error(
		    std::make_error_code(std::errc::address_family_not_supported),
		    "sock_port unsupported address family"
		);
	}
	
	unsigned short sockaddr_port_noexcept(const sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<const sockaddr_in6 *>(addr)->sin6_port;
			return ntohs(port);
		}
		
		return 0;
	}

	void addrinfo_deleter::operator ()(addrinfo_type * ptr) const noexcept
	{
		FreeAddrInfoW(ptr);
	}

	int close(socket_handle_type sock) noexcept
	{
		return sock != invalid_socket ? ::closesocket(sock) : 0;
	}

	/************************************************************************/
	/*                   getaddrinfo                                        */
	/************************************************************************/
	addrinfo_uptr getaddrinfo(const wchar_t * host, const wchar_t * service, const addrinfo_type * hints, std::error_code & err)
	{
		addrinfo_type * ptr;
		int res = ::GetAddrInfoW(host, service, hints, &ptr);
		if (res == 0)
		{
			err.clear();
			return addrinfo_uptr(ptr);
		}
		else
		{
			err.assign(res, std::system_category());
			return nullptr;
		}
	}
	
	addrinfo_uptr getaddrinfo(const wchar_t * host, const wchar_t * service, const addrinfo_type * hints)
	{
		addrinfo_type * ptr;
		int res = ::GetAddrInfoW(host, service, hints, &ptr);
		if (res == 0)
			return addrinfo_uptr(ptr);
		else
			throw_socket_error(res, "GetAddrInfoW failed");
	}
	
	addrinfo_uptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints, std::error_code & err)
	{
		std::wstring whoststr, wservicestr;

		const wchar_t * whost = nullptr;
		const wchar_t * wservice = nullptr;

		if (host)
		{
			auto in = boost::make_iterator_range_n(host, std::strlen(host));
			wchar_cvt::to_wchar(in, whoststr);
			whost = whoststr.c_str();
		}

		if (service)
		{
			auto in = boost::make_iterator_range_n(service, std::strlen(service));
			wchar_cvt::to_wchar(in, wservicestr);
			wservice = wservicestr.c_str();
		}

		return getaddrinfo(whost, wservice, hints, err);
	}

	addrinfo_uptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints)
	{
		std::wstring whoststr, wservicestr;

		const wchar_t * whost = nullptr;
		const wchar_t * wservice = nullptr;

		if (host)
		{
			auto in = boost::make_iterator_range_n(host, std::strlen(host));
			wchar_cvt::to_wchar(in, whoststr);
			whost = whoststr.c_str();
		}

		if (service)
		{
			auto in = boost::make_iterator_range_n(service, std::strlen(service));
			wchar_cvt::to_wchar(in, whoststr);
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
	void init_socket_library()
	{
#ifdef EXT_ENABLE_OPENSSL
		ext::openssl::ssl_init();
#endif
	}
	
	void free_socket_library()
	{
#ifdef EXT_ENABLE_OPENSSL
		ext::openssl::lib_cleanup();
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

				// it was eof
				if (res == 0)
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
			if (addr->ai_family == AF_INET or addr->ai_family == AF_INET6)
				reinterpret_cast<sockaddr_in *>(addr->ai_addr)->sin_port = htons(port);
	}

	auto get_port(addrinfo_type * addr) -> unsigned short
	{
		// both sockaddr_in6 and sockaddr_in have port member on same offset
		if (addr->ai_family == AF_INET or addr->ai_family == AF_INET6)
		{
			unsigned short port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
			return ntohs(port);
		}
		
		return 0;
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

	void inet_ntop(const  in_addr * addr, std::string & str)
	{
		const char * res;
		socklen_t buflen = INET_ADDRSTRLEN;
		char buffer[INET_ADDRSTRLEN];
		res = ::inet_ntop(AF_INET, addr, buffer, buflen);
		
		if (res == nullptr)
			throw_last_socket_error("inet_ntop failed");
		
		str.assign(res);
	}
	
	auto inet_ntop(const  in_addr * addr) -> std::string
	{
		std::string str;
		inet_ntop(addr, str);
		return str;
	}
	
	void inet_ntop(const in6_addr * addr, std::string & str)
	{
		const char * res;
		socklen_t buflen = INET6_ADDRSTRLEN;
		char buffer[INET6_ADDRSTRLEN];
		res = ::inet_ntop(AF_INET6, addr, buffer, buflen);
		
		if (res == nullptr)
			throw_last_socket_error("inet_ntop failed");
		
		str.assign(res);
	}
	
	auto inet_ntop(const in6_addr * addr) -> std::string
	{
		std::string str;
		inet_ntop(addr, str);
		return str;
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

	bool inet_pton(const char * addr, in_addr * out)
	{
		int res = ::inet_pton(AF_INET, addr, out);
		if (res == -1)
			throw_last_socket_error("inet_pton failed");
		return res > 0;
	}
	
	bool inet_pton(const std::string & addr, in_addr * out)
	{
		int res = ::inet_pton(AF_INET, addr.c_str(), out);
		if (res == -1)
			throw_last_socket_error("inet_pton failed");
		return res > 0;
	}
	
	bool inet_pton(const char * addr, in6_addr * out)
	{
		int res = ::inet_pton(AF_INET6, addr, out);
		if (res == -1)
			throw_last_socket_error("inet_pton failed");
		return res > 0;
	}
	
	bool inet_pton(const std::string & addr, in6_addr * out)
	{
		int res = ::inet_pton(AF_INET6, addr.c_str(), out);
		if (res == -1)
			throw_last_socket_error("inet_pton failed");
		return res > 0;
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

	void setsock_nonblocking(socket_handle_type sock, bool nonblocking)
	{
		int res = ::fcntl(sock, F_SETFL, ::fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
		if (res != 0) throw_last_socket_error("ext::net::setsock_nonblocking failed");
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

	std::string sockaddr_endpoint(const sockaddr * addr)
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

	std::string sockaddr_endpoint_noexcept(const sockaddr * addr)
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

	unsigned short sockaddr_port(const sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<const sockaddr_in6 *>(addr)->sin6_port;
			return ntohs(port);
		}
		
		throw std::system_error(
		    std::make_error_code(std::errc::address_family_not_supported),
		    "sock_port unsupported address family"
		);
	}
	
	unsigned short sockaddr_port_noexcept(const sockaddr * addr)
	{
		if (addr->sa_family == AF_INET or addr->sa_family == AF_INET6)
		{
			// both sockaddr_in6 and sockaddr_in have port member on same offset
			auto port = reinterpret_cast<const sockaddr_in6 *>(addr)->sin6_port;
			return ntohs(port);
		}
		
		return 0;
	}

	void addrinfo_deleter::operator ()(addrinfo_type * ptr) const noexcept
	{
		::freeaddrinfo(ptr);
	}

	int close(socket_handle_type sock) noexcept
	{
		return sock != invalid_socket ? ::close(sock) : 0;
	}
	
	addrinfo_uptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints)
	{
		std::error_code err;
		auto result = getaddrinfo(host, service, hints, err);
		if (result) return result;

		throw std::system_error(err, "getaddrinfo failed");
	}

	addrinfo_uptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints, std::error_code & err)
	{
		addrinfo_type * ptr;
		int res = ::getaddrinfo(host, service, hints, &ptr);
		if (res == 0)
		{
			err.clear();
			return addrinfo_uptr(ptr);
		}

		if (res == EAI_SYSTEM)
		{
			err.assign(errno, std::generic_category());
			return addrinfo_uptr(nullptr);
		}
		else
		{
			err.assign(res, gai_error_category());
			return addrinfo_uptr(nullptr);
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
	void getpeername(socket_handle_type sock, sockaddr_type * addr, socklen_t * addrlen)
	{
		auto res = ::getpeername(sock, addr, addrlen);
		if (res != 0)
			throw_last_socket_error("ext::net::getpeername failure");
	}

	void getsockname(socket_handle_type sock, sockaddr_type * addr, socklen_t * addrlen)
	{
		auto res = ::getsockname(sock, addr, addrlen);
		if (res != 0)
			throw_last_socket_error("ext::net::getsockname failure");
	}
	
	std::string peer_endpoint(socket_handle_type sock)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		ext::net::getpeername(sock, addr, &addrlen);

		return ext::net::sockaddr_endpoint(addr);
	}

	std::string sock_endpoint(socket_handle_type sock)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		ext::net::getsockname(sock, addr, &addrlen);

		return ext::net::sockaddr_endpoint(addr);
	}

	std::string peer_endpoint_noexcept(socket_handle_type sock)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		auto res = ::getpeername(sock, addr, &addrlen);
		if (res != 0) return ext::net::make_addr_error_description(errno);

		return ext::net::sockaddr_endpoint_noexcept(addr);
	}

	std::string sock_endpoint_noexcept(socket_handle_type sock)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		auto res = ::getsockname(sock, addr, &addrlen);
		if (res != 0) return ext::net::make_addr_error_description(errno);

		return ext::net::sockaddr_endpoint_noexcept(addr);
	}

	unsigned short peer_port(socket_handle_type sock)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		ext::net::getpeername(sock, addr, &addrlen);

		return ext::net::sockaddr_port(addr);
	}

	unsigned short sock_port(socket_handle_type sock)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		ext::net::getsockname(sock, addr, &addrlen);

		return ext::net::sockaddr_port(addr);
	}

	void peer_name(socket_handle_type sock, std::string & name, unsigned short & port)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		ext::net::getpeername(sock, addr, &addrlen);

		ext::net::inet_ntop(addr, name, port);
	}

	void sock_name(socket_handle_type sock, std::string & name, unsigned short & port)
	{
		sockaddr_storage addrstore;
		socklen_t addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		ext::net::getsockname(sock, addr, &addrlen);

		ext::net::inet_ntop(addr, name, port);
	}

	auto peer_name(socket_handle_type sock) -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		ext::net::peer_name(sock, res.first, res.second);
		return res;
	}

	auto sock_name(socket_handle_type sock) -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		ext::net::sock_name(sock, res.first, res.second);
		return res;
	}

	std::string peer_address(socket_handle_type sock)
	{
		std::string addr; unsigned short port;
		ext::net::peer_name(sock, addr, port);
		return addr;
	}

	std::string sock_address(socket_handle_type sock)
	{
		std::string addr; unsigned short port;
		ext::net::sock_name(sock, addr, port);
		return addr;
	}

	
	void shutdown(socket_handle_type handle, int how)
	{
		if (handle == invalid_socket) return;

		int res = ::shutdown(handle, how);
		if (res != 0) throw_last_socket_error("shutdown failed");
	}
	
	addrinfo_uptr loopback_addr(int address_family, int sock_type, int sock_proto)
	{
		std::error_code err;
		auto result = loopback_addr(err, address_family, sock_type, sock_proto);
		if (result) return result;
		
		throw std::system_error(err, "loopback_addr failed");
	}
	
	addrinfo_uptr loopback_addr(std::error_code & err, int address_family, int sock_type, int sock_proto)
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
		hints.ai_flags = AI_ADDRCONFIG | AI_ALL | AI_NUMERICHOST | AI_NUMERICSERV;
		hints.ai_family = address_family;
		hints.ai_socktype = sock_type;
		hints.ai_protocol = sock_proto;
		
		// If node is NULL and AI_PASSIVE is not set in hints - then the network address will be set to the loopback interface address
		// (INADDR_LOOPBACK for IPv4 addresses, IN6ADDR_LOOPBACK_INIT for IPv6 address)
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
		
		assert(sockaddr_port(addr_info->ai_addr) == 0);
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
		
		assert(sockaddr_port(addr_info->ai_addr) == 0);
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
