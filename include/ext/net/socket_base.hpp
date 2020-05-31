#pragma once
#include <memory>
#include <chrono>
#include <type_traits>
#include <system_error>

#include <boost/predef.h>

#include <ext/config.hpp>
#include <ext/net/socket_fwd.hpp>

namespace ext::net
{

#if BOOST_OS_WINDOWS

	using addrinfo_type = addrinfoW;
	using sockaddr_type = sockaddr;

	/// winsock initialization functons, brouht here for windows include isolation
	/// calss WSAstartup and returns call result
	int wsastartup(std::uint16_t version);
	/// calls WSAstartup with version 2.2.
	/// if call ends with failure - prints error message into std::cerr and calls std::exit(EXIT_FAILURE).
	/// For better control - call directly WSAStartup or int wsastartup(std::uint16_t version)
	void wsastartup();
	/// calls WSACleanup
	void wsacleanup();

	/// initializes libraries needed for working with sockets.
	/// this are winosock2 and, if enabled, OpenSSL.
	/// in fact calls ext::net::wsastratup(); ext::net::openssl_init()
	void socket_stream_init();

#else

	using addrinfo_type = addrinfo;
	using sockaddr_type = sockaddr;

	/// initializes libraries needed for working with sockets.
	/// this is, if enabled, OpenSSL. In fact calls ext::net::openssl_init()
	void socket_stream_init();

#endif

	/// socket error condition, this is NOT error codes,
	/// this is convenience conditions socket can be tested on.
	///
	/// you should use them like:
	///  * if (ss.last_error() == sock_errc::error) std::cerr << ss.last_error ...
	///  * if (ss.last_error() == sock_errc::regular) { ... process result ... }
	enum class sock_errc
	{
		eof         = 1,   /// socket eof, for example recv return 0, or OpenSSL returned SSL_ERR_ZERO_RETURN
		would_block = 2,   /// operation would block, not a error
		timeout     = 3,   /// operation(connect, read, write, shutdown) timeout
		regular     = 4,   /// no a error, code == 0 or some error which is not critical, like eof(currently only eof, would_block)
		error       = 5,   /// opposite of regular, some bad unexpected error, which breaks normal flow, timeout, system error, etc
		ssl_error   = 6,   /// ssl related error(but not openssl_error::zero_return)
	};

	const std::error_category & socket_condition_category() noexcept;

	/// integration with system_error
	inline std::error_code make_error_code(sock_errc val)           noexcept { return {static_cast<int>(val), socket_condition_category()}; }
	inline std::error_condition make_error_condition(sock_errc val) noexcept { return {static_cast<int>(val), socket_condition_category()}; }
}

namespace std
{
	template <>
	struct is_error_condition_enum<ext::net::sock_errc>
		: std::true_type {};
}

namespace ext::net
{
	struct addrinfo_deleter
	{
		void operator()(addrinfo_type * ptr) const;
	};

	using addrinfo_ptr = std::unique_ptr<addrinfo_type, addrinfo_deleter>;
	constexpr socket_handle_type invalid_socket = -1;

	// special tag type, to disambiguate some overloaded constructors accepting socket handles(int type) and port(unsigned short type)
	// ext::net::listener listener(handle_arg, handle);
	struct handle_arg_type {} constexpr handle_arg;
	
	/// on POSIX systems - return ::close(sock)
	/// on WINDOWS       - return ::closesocket(sock);
	int close(socket_handle_type sock);

	/// error category for network address and service translation.
	/// EAI_* codes, gai_strerror
	const std::error_category & gai_error_category();

	/// returns last socket error
	int last_socket_error() noexcept;
	/// returns socket error category:
	/// on POSIX systems it's std::generic_category(), or windows - std::system_category
	const std::error_category & socket_error_category() noexcept;
	/// returns last socket error
	std::error_code last_socket_error_code() noexcept;

	BOOST_NORETURN void throw_socket_error(int code, const char * errmsg);
	BOOST_NORETURN void throw_socket_error(int code, const std::string & errmsg);
	BOOST_NORETURN void throw_last_socket_error(const std::string & errmsg);
	BOOST_NORETURN void throw_last_socket_error(const char * errmsg);

	std::error_code socket_rw_error(int res, int last_error = last_socket_error());

#ifdef EXT_ENABLE_OPENSSL
	std::error_code socket_ssl_rw_error(int res, SSL * ssl);
#endif

	void set_port(addrinfo_type * addr, unsigned short port);
	auto get_port(addrinfo_type * addr) -> unsigned short;
	void make_timeval(std::chrono::steady_clock::duration val, timeval & tv);
	int poll_mktimeout(std::chrono::steady_clock::duration val);

	/// ::inet_ntop wrapper, все строки в utf8
	/// @Throws std::system_error в случае системной ошибки
	void inet_ntop(const sockaddr * addr, std::string & str, unsigned short & port);
	auto inet_ntop(const sockaddr * addr) -> std::pair<std::string, unsigned short>;

#if BOOST_OS_WINDOWS
	/// ::inet_ntop wrapper, все строки в utf16
	/// @Throws std::system_error в случае системной ошибки
	///         ext::codecvt_convert::conversion_failure(std::runtime_error derived)
	///              при ошибках конвертации utf-8 <-> utf-16
	void inet_ntop(const sockaddr * addr, std::wstring & wstr, unsigned short & port);
#endif

	/// ::inet_pton wrapper, все строки в utf8
	/// @Return false если входная строка содержит не валидный адрес
	/// @Throws std::system_error в случае системной ошибки
	bool inet_pton(int family, const char * addr, sockaddr * out);
	bool inet_pton(int family, const std::string & addr, sockaddr * out);

#if BOOST_OS_WINDOWS
	/// ::inet_pton wrapper для winsock платформы, все строки в utf16
	/// @Return false если входная строка содержит не валидный адрес
	/// @Throws std::system_error в случае системной ошибки
	///         ext::codecvt_convert::conversion_failure(std::runtime_error derived)
	///              при ошибках конвертации utf-8 <-> utf-16
	bool inet_pton(int family, const wchar_t * waddr, sockaddr * out);
	bool inet_pton(int family, const std::wstring & waddr, sockaddr * out);
#endif

	/// создает строку вида <ERR:code>, например <ENOTCONN:107>,
	/// поддерживает только ряд кодов, связанных с функциями получения.конвертация адресов: getpeername, getsockname, inet_pton, etc
	std::string make_addr_error_description(int err);
	/// возвращает строку адреса подключения вида $addr:$port, например 127.0.0.1:22, для ipv6 - [::1]:22
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	std::string sock_addr(sockaddr * addr);
	/// safe версия sock_add - не кидает ошибок(за исключением std::bad_alloc),
	/// в случае ошибки возвращает <ERR:code>. Например - <ENOTCONN:107>
	std::string sock_addr_noexcept(sockaddr * addr);

	/// \{
	///
	/// ::getaddrinfo wrapper, все строки в utf8
	/// hints.ai_family = AF_UNSPEC
	/// hints.ai_protocol = IPPROTO_TCP
	/// hints.ai_socktype = SOCK_STREAM
	///
	/// @Param host имя или адрес как в ::getaddrinfo
	/// @Param service/port имя сервиса или номер порта как в ::getaddrinfo
	/// @Param err для nothrow overload, out параметр, тут будет ошибка, а возвращаемое значение будет null
	/// @Returns std::unique_ptr<addrinfo> resolved адрес, в случае ошибки - nullptr для error overloads
	/// @Throws std::system_error в случае системной ошибки

	addrinfo_ptr getaddrinfo(const char * host, const char * service);
	addrinfo_ptr getaddrinfo(const char * host, const char * service, std::error_code & err);

	inline addrinfo_ptr getaddrinfo(const std::string & host, const std::string & service, std::error_code & err) { return getaddrinfo(host.c_str(), service.c_str(), err); }
	inline addrinfo_ptr getaddrinfo(const std::string & host, std::error_code & err)                              { return getaddrinfo(host.c_str(), nullptr, err); }
	inline addrinfo_ptr getaddrinfo(const std::string & host, const std::string & service)                        { return getaddrinfo(host.c_str(), service.c_str()); }
	inline addrinfo_ptr getaddrinfo(const std::string & host)                                                     { return getaddrinfo(host.c_str(), nullptr); }

#if BOOST_OS_WINDOWS
	addrinfo_ptr getaddrinfo(const wchar_t * host, const wchar_t * service);
	addrinfo_ptr getaddrinfo(const wchar_t * host, const wchar_t * service, std::error_code & err);

	inline addrinfo_ptr getaddrinfo(const std::wstring & host, const std::wstring & service, std::error_code & err)  { return getaddrinfo(host.c_str(), service.c_str(), err); }
	inline addrinfo_ptr getaddrinfo(const std::wstring & host, std::error_code & err)                                { return getaddrinfo(host.c_str(), nullptr, err); }
	inline addrinfo_ptr getaddrinfo(const std::wstring & host, const std::wstring & service)                         { return getaddrinfo(host.c_str(), service.c_str()); }
	inline addrinfo_ptr getaddrinfo(const std::wstring & host)                                                       { return getaddrinfo(host.c_str(), nullptr); }
#endif

	/// \}
}
