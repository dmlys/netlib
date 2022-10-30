#pragma once
#include <memory>
#include <chrono>
#include <type_traits>
#include <system_error>

#include <boost/predef.h>

#include <ext/config.hpp>
#include <ext/net/socket_fwd.hpp>
#include <ext/unique_handle.hpp>

namespace ext::net
{
	extern const int af_unspec;  // AF_UNSPEC
	extern const int af_inet;    // AF_INET
	extern const int af_inet6;   // AF_INET6
	
	extern const int sock_stream;    // SOCK_STREAM
	extern const int sock_dgram;     // SOCK_DGRAM
	extern const int sock_seqpacket; // SOCK_SEQPACKET

	extern const int msg_nosignal;   // MSG_NOSIGNAL or 0 if not defined
	

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

	/// Initializes libraries needed for working with sockets.
	/// This are winsock2 and, if enabled, OpenSSL.
	/// In fact calls ext::net::wsastratup(); ext::openssl_init()
	void socket_stream_init();
	/// Deinitializes libraries needed for working with sockets.
	/// This are winsock2 and, if enabled, OpenSSL.
	/// In fact calls ext::net::wsacleanup(); ext::openssl_cleanup()
	void socket_stream_cleanup();
	
#else

	using addrinfo_type = addrinfo;
	using sockaddr_type = sockaddr;

	/// Initializes libraries needed for working with sockets.
	/// This is, if enabled, OpenSSL. In fact calls ext::openssl_init()
	void socket_stream_init();
	/// Deinitializes libraries needed for working with sockets.
	/// This is, if enabled, OpenSSL. In fact calls ext::openssl_cleanup()
	void socket_stream_cleanup();
	
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
	/// not a socket/invalid socket value
	constexpr socket_handle_type invalid_socket = -1;
	
	/// on POSIX systems - return ::close(sock)
	/// on WINDOWS       - return ::closesocket(sock);
	int close(socket_handle_type sock) noexcept;
	
	struct addrinfo_deleter
	{
		void operator()(addrinfo_type * ptr) const noexcept;
	};

	struct socket_closer
	{
		static void close(socket_handle_type sock) noexcept { ext::net::close(sock); }
		static auto emptyval() noexcept -> socket_handle_type { return invalid_socket; }
	};
	
	using addrinfo_uptr = std::unique_ptr<addrinfo_type, addrinfo_deleter>;
	using socket_uhandle = ext::unique_handle<socket_handle_type, socket_closer>;

	// special tag type, to disambiguate some overloaded constructors accepting socket handles(int type) and port(unsigned short type)
	// ext::net::listener listener(handle_arg, handle);
	struct handle_arg_type {} constexpr handle_arg;

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

	/// throws std::system_error with given socket error code and message
	BOOST_NORETURN void throw_socket_error(int code, const char * errmsg);
	BOOST_NORETURN void throw_socket_error(int code, const std::string & errmsg);
	/// throws std::system_error with last socket error and given message
	BOOST_NORETURN void throw_last_socket_error(const std::string & errmsg);
	BOOST_NORETURN void throw_last_socket_error(const char * errmsg);

	/// Analyzes socket read/write operation error and returns it.
	/// res - result of recv/send operation, if res >= 0 - this is eof
	/// last_error - error code: errno/getsockopt(..., SO_ERROR, ...)
	std::error_code socket_rw_error(int res, int last_error = last_socket_error());

#ifdef EXT_ENABLE_OPENSSL
	/// Analyzes socket SSL read/write operation error and returns it.
	/// res - result of SSL operation: ::SSL_read/SSL_write,
	/// This functions uses SSL_get_error(ssl, res) call to get SSL error,
	/// and in case of SSL_ERROR_SYSCALL further checks for ERR_peek_error
	std::error_code socket_ssl_rw_error(int res, SSL * ssl);
#endif

	void set_port(addrinfo_type * addr, unsigned short port);
	auto get_port(addrinfo_type * addr) -> unsigned short;
	
	void make_timeval(std::chrono::steady_clock::duration val, timeval & tv);
	int poll_mktimeout(std::chrono::steady_clock::duration val);
	
	/// overflow safe timeout addition, if adding timeout will overflow - returns std::chrono::steady_clock::time_point::max()
	auto add_timeout(std::chrono::steady_clock::time_point tp, std::chrono::steady_clock::duration timeout) -> std::chrono::steady_clock::time_point;
	/// overflow safe timeout addition, if adding timeout will overflow - returns std::chrono::steady_clock::duration::max()
	auto add_timeout(std::chrono::steady_clock::duration dur, std::chrono::steady_clock::duration timeout) -> std::chrono::steady_clock::duration;

	/// ::inet_ntop wrapper, все строки в utf8
	/// @Throws std::system_error в случае системной ошибки
	void inet_ntop(const  in_addr * addr, std::string & str);
	auto inet_ntop(const  in_addr * addr) -> std::string;
	void inet_ntop(const in6_addr * addr, std::string & str);
	auto inet_ntop(const in6_addr * addr) -> std::string;
	/// ::inet_ntop wrapper, все строки в utf8
	/// @Throws std::system_error в случае системной ошибки
	void inet_ntop(const sockaddr * addr, std::string & str, unsigned short & port);
	auto inet_ntop(const sockaddr * addr) -> std::pair<std::string, unsigned short>;

#if BOOST_OS_WINDOWS
	/// ::inet_ntop wrapper, все строки в utf16
	/// @Throws std::system_error в случае системной ошибки
	///         ext::codecvt_convert::conversion_failure(std::runtime_error derived)
	///              при ошибках конвертации utf-8 <-> utf-16
	void inet_ntop(const  in_addr * addr, std::wstring & str);
	void inet_ntop(const in6_addr * addr, std::wstring & str);
	void inet_ntop(const sockaddr * addr, std::wstring & wstr, unsigned short & port);
#endif

	/// ::inet_pton wrapper, все строки в utf8
	/// @Return false если входная строка содержит не валидный адрес
	/// @Throws std::system_error в случае системной ошибки
	bool inet_pton(const char * addr, in_addr * out);
	bool inet_pton(const std::string & addr, in_addr * out);
	bool inet_pton(const char * addr, in6_addr * out);
	bool inet_pton(const std::string & addr, in6_addr * out);
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
	bool inet_pton(const wchar_t * addr, in_addr * out);
	bool inet_pton(const std::wstring & addr, in_addr * out);
	bool inet_pton(const wchar_t * addr, in6_addr * out);
	bool inet_pton(const std::wstring & addr, in6_addr * out);
	bool inet_pton(int family, const wchar_t * waddr, sockaddr * out);
	bool inet_pton(int family, const std::wstring & waddr, sockaddr * out);
#endif

	/// ::fcntl(sock, F_SETFL, ::fcntl(sock, F_GETFL, 0) | O_NONBLOCK) wrapper
	/// @Throws std::system_error in case of errors
	void setsock_nonblocking(socket_handle_type sock, bool nonblocking = true);
	
	
	/// создает строку вида <ERR:code>, например <ENOTCONN:107>,
	/// поддерживает только ряд кодов, связанных с функциями получения/конвертация адресов: getpeername, getsockname, inet_pton, etc
	std::string make_addr_error_description(int err);
	/// возвращает строку адреса подключения вида $addr:$port, например 127.0.0.1:22, для ipv6 - [::1]:22
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	std::string sockaddr_endpoint(const sockaddr * addr);
	/// safe версия sockaddr_endpoint - не кидает ошибок(за исключением std::bad_alloc),
	/// в случае ошибки возвращает <ERR:code>. Например - <ENOTCONN:107>
	std::string sockaddr_endpoint_noexcept(const sockaddr * addr);
	/// возвращает порт подключения,
	/// если address family не поддерживает порт как таковой - кидает std::runtime_error / std::system_error
	unsigned short sockaddr_port(const sockaddr * addr);
	/// safe версия sockaddr_port - не кидает исключений,
	/// если address family не поддерживает порт как таковой - возвращает 0
	unsigned short sockaddr_port_noexcept(const sockaddr * addr);
	
	
	/// вызов ::getpeername(sock, addr, addrlen), + проверка результат
	/// в случае ошибок кидает исключение system_error_type
	void getpeername(socket_handle_type sock, sockaddr_type * addr, socklen_t * addrlen);
	/// вызов ::getsockname(sock, addr, namelen), + проверка результат
	/// в случае ошибок кидает исключение system_error_type
	void getsockname(socket_handle_type sock, sockaddr_type * addr, socklen_t * addrlen);
		
	/// возвращает строку адреса подключения вида <addr:port>(функция getpeername)
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	std::string peer_endpoint(socket_handle_type sock);
	/// safe версия peer_endpoint - не кидает ошибок(за исключением std::bad_alloc),
	/// в случае ошибки возвращает <ERR:code>. Например - <ENOTCONN:107>
	std::string peer_endpoint_noexcept(socket_handle_type sock);
	/// возвращает строку адреса и порт подключения (функция getpeername).
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	void peer_name(socket_handle_type sock, std::string & name, unsigned short & port);
	auto peer_name(socket_handle_type sock) -> std::pair<std::string, unsigned short>;
	/// возвращает строку адреса подключения (функция getpeername)
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	std::string peer_address(socket_handle_type sock);
	/// возвращает порт подключения (функция getpeername)
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	unsigned short peer_port(socket_handle_type sock);

	/// возвращает строку адреса подключения вида <addr:port>(функция getsockname)
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	std::string sock_endpoint(socket_handle_type sock);
	/// safe версия sock_endpoint - не кидает ошибок(за исключением std::bad_alloc),
	/// в случае ошибки возвращает <ERR:code>. Например - <ENOTCONN:107>
	std::string sock_endpoint_noexcept(socket_handle_type sock);
	/// возвращает строку адреса и порт подключения (функция getsockname).
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	void sock_name(socket_handle_type sock, std::string & name, unsigned short & port);
	auto sock_name(socket_handle_type sock) -> std::pair<std::string, unsigned short>;
	/// возвращает строку адреса подключения (функция getsockname)
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	std::string sock_address(socket_handle_type sock);
	/// возвращает порт подключения (функция getsockname)
	/// в случае ошибок кидает исключение std::runtime_error / std::system_error
	unsigned short sock_port(socket_handle_type sock);
	
	
	
	/// \{
	///
	/// ::getaddrinfo wrapper, все строки в utf8
	///
	/// @Param host имя или адрес как в ::getaddrinfo
	/// @Param service/port имя сервиса или номер порта как в ::getaddrinfo
	/// @Param hints передается как есть в вызов ::getaddrinfo,
	///              null допустимое значение - в таком случае как привило используются некие default значение
	/// @Param err для nothrow overload, out параметр, тут будет ошибка, а возвращаемое значение будет null
	/// @Returns std::unique_ptr<addrinfo> resolved адрес, в случае ошибки - nullptr для error overloads
	/// @Throws std::system_error в случае системной ошибки

	addrinfo_uptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints);
	addrinfo_uptr getaddrinfo(const char * host, const char * service, const addrinfo_type * hints, std::error_code & err);
	
	inline addrinfo_uptr getaddrinfo(const char * host, const char * service)                          { return getaddrinfo(host, service, nullptr); }
	inline addrinfo_uptr getaddrinfo(const char * host, const char * service, std::error_code & err)   { return getaddrinfo(host, service, nullptr, err); }

	inline addrinfo_uptr getaddrinfo(const std::string & host, const std::string & service, std::error_code & err) { return getaddrinfo(host.c_str(), service.c_str(), err); }
	inline addrinfo_uptr getaddrinfo(const std::string & host, std::error_code & err)                              { return getaddrinfo(host.c_str(), nullptr, err); }
	inline addrinfo_uptr getaddrinfo(const std::string & host, const std::string & service)                        { return getaddrinfo(host.c_str(), service.c_str()); }
	inline addrinfo_uptr getaddrinfo(const std::string & host)                                                     { return getaddrinfo(host.c_str(), nullptr); }

#if BOOST_OS_WINDOWS
	addrinfo_uptr getaddrinfo(const wchar_t * host, const wchar_t * service, const addrinfo_type * hints);
	addrinfo_uptr getaddrinfo(const wchar_t * host, const wchar_t * service, const addrinfo_type * hints, std::error_code & err);

	inline addrinfo_uptr getaddrinfo(const wchar_t * host, const wchar_t * service)                           { return getaddrinfo(host, service, nullptr); }
	inline addrinfo_uptr getaddrinfo(const wchar_t * host, const wchar_t * service, std::error_code & err)    { return getaddrinfo(host, service, nullptr, err); }
	
	inline addrinfo_uptr getaddrinfo(const std::wstring & host, const std::wstring & service, std::error_code & err)  { return getaddrinfo(host.c_str(), service.c_str(), err); }
	inline addrinfo_uptr getaddrinfo(const std::wstring & host, std::error_code & err)                                { return getaddrinfo(host.c_str(), nullptr, err); }
	inline addrinfo_uptr getaddrinfo(const std::wstring & host, const std::wstring & service)                         { return getaddrinfo(host.c_str(), service.c_str()); }
	inline addrinfo_uptr getaddrinfo(const std::wstring & host)                                                       { return getaddrinfo(host.c_str(), nullptr); }
#endif

	/// \}


	/// calls ::shutdown and checks result,
	/// throws std::system_error in case or errors
	void shutdown(socket_handle_type handle, int how);
	
	/// Returns loopback addr with port = 0 for given address family, socket type and protocol.
	/// Resolution will be done with AI_ADDRCONFIG, so addr family in case of AF_UNSPEC, will depend on system configuration
	addrinfo_uptr loopback_addr(int address_family = af_unspec, int sock_type = sock_stream, int sock_proto = 0);
	addrinfo_uptr loopback_addr(std::error_code & err, int address_family = af_unspec, int sock_type = sock_stream, int sock_proto = 0);
	
	/// manual implementation of socket pair function.
	/// This function creates listener with loopback address and zero port(port will be assigned by OS),
	/// connects socket to created listener and returns connected socket pair.
	void manual_socketpair(socket_handle_type fds[2], int address_family = af_unspec, int sock_type = 0, int sock_proto = 0);
	bool manual_socketpair(socket_handle_type fds[2], std::error_code & err, int address_family = af_unspec, int sock_type = 0, int sock_proto = 0);
	
	/// socket pair wrapper, if socketpair system call is not available on this platform, it will be done via manual_socketpair
	void socketpair(socket_handle_type fds[2], int address_family = af_unspec, int sock_type = 0, int sock_proto = 0);
	bool socketpair(socket_handle_type fds[2], std::error_code & err, int address_family = af_unspec, int sock_type = 0, int sock_proto = 0);
}
