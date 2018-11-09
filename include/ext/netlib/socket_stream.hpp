#pragma once
#include <string>
#include <ostream>
#include <istream>

#include <ext/netlib/socket_base.hpp>
#include <ext/netlib/socket_streambuf.hpp>

namespace ext::netlib
{
	/// реализация iostream для сокета.
	/// подробнее смотри socket_streambuf
	class socket_stream : public std::iostream
	{
		socket_streambuf m_streambuf;

	public:
		typedef socket_streambuf::error_code_type     error_code_type;
		typedef socket_streambuf::system_error_type   system_error_type;
		typedef socket_streambuf::duration_type       duration_type;
		typedef socket_streambuf::time_point          time_point;
		typedef socket_streambuf::handle_type         handle_type;

	public:
		/************************************************************************/
		/*                 forward some methods                                 */
		/************************************************************************/
		bool self_tie() const   { return m_streambuf.self_tie(); }
		bool self_tie(bool tie) { return m_streambuf.self_tie(tie); }

		duration_type timeout() const noexcept { return m_streambuf.timeout(); }
		duration_type timeout(duration_type newtimeout) noexcept { return m_streambuf.timeout(newtimeout); }

		const error_code_type & last_error() const noexcept { return m_streambuf.last_error(); }
		const char * last_error_context() const noexcept { return m_streambuf.last_error_context(); }
		void set_last_error(error_code_type errc, const char * context = nullptr) noexcept { return m_streambuf.set_last_error(errc, context); }

		socket_streambuf * rdbuf() noexcept { return &m_streambuf; }
		handle_type handle() const noexcept { return m_streambuf.handle(); }

		void getpeername(sockaddr_type * addr, socklen_t * addrlen) { m_streambuf.getpeername(addr, addrlen); }
		void getsockname(sockaddr_type * addr, socklen_t * addrlen) { m_streambuf.getsockname(addr, addrlen); }

		std::string peer_endpoint() { return m_streambuf.peer_endpoint(); }
		void peer_name(std::string & name, unsigned short & port)  { return m_streambuf.peer_name(name, port); }
		auto peer_name() -> std::pair<std::string, unsigned short> { return m_streambuf.peer_name(); }
		std::string peer_address() { return m_streambuf.peer_address(); }
		unsigned short peer_port() { return m_streambuf.peer_port(); }

		std::string sock_endpoint() { return m_streambuf.sock_endpoint(); }
		void sock_name(std::string & name, unsigned short & port)  { return m_streambuf.sock_name(name, port); }
		auto sock_name() -> std::pair<std::string, unsigned short> { return m_streambuf.sock_name(); }
		std::string sock_address() { return m_streambuf.sock_address(); }
		unsigned short sock_port() { return m_streambuf.sock_port(); }



		/// подключение не валидно, если оно не открыто или была ошибка в процессе работы
		bool is_valid() const noexcept { return m_streambuf.is_valid(); }
		/// подключение открыто, если была попытка подключения, даже если не успешная.
		/// если resolve завершился неудачей - класс не считается открытым
		bool is_open() const noexcept { return m_streambuf.is_open(); }

		/// выоляет подключение rdbuf()->connect(host, port);
		/// в случае ошибки устанавливает failbit | badbit
		void connect(const std::string & host, unsigned short port);
		/// выоляет подключение rdbuf()->connect(host, service);
		/// в случае ошибки устанавливает failbit | badbit
		void connect(const std::string & host, const std::string & service);

#if BOOST_OS_WINDOWS
		/// выоляет подключение rdbuf()->connect(host, port);
		/// в случае ошибки устанавливает failbit | badbit
		void connect(const std::wstring & host, unsigned short port);
		/// выоляет подключение rdbuf()->connect(host, service);
		/// в случае ошибки устанавливает failbit | badbit
		void connect(const std::wstring & host, const std::wstring & service);
#endif // BOOST_OS_WINDOWS


#ifdef EXT_ENABLE_OPENSSL
		bool ssl_started() const { return m_streambuf.ssl_started(); }
		SSL * ssl_handle() { return m_streambuf.ssl_handle(); }
		void set_ssl(SSL * ssl) { return m_streambuf.set_ssl(ssl); }
		/// rdbuf()->start_ssl(...)
		/// в случае ошибки устанавливает failbit | badbit
		void start_ssl();
		void start_ssl(SSL_CTX * sslctx);
		void start_ssl(const SSL_METHOD * sslmethod);
		void start_ssl(const std::string & servername);
		void start_ssl(const SSL_METHOD * sslmethod, const std::string & servername);

#if BOOST_OS_WINDOWS
		void start_ssl(const std::wstring & servername);
		void start_ssl(const SSL_METHOD * sslmethod, const std::wstring & wservername);
#endif // BOOST_OS_WINDOWS

		/// rdbuf()->accept_ssl(...)
		/// в случае ошибки устанавливает failbit | badbit
		void accept_ssl(SSL_CTX * sslctx);

		/// rdbuf()->stop_ssl()
		/// в случае ошибки устанавливает failbit | badbit
		void stop_ssl();
		/// rdbuf()->free_ssl();
		void free_ssl() { return m_streambuf.free_ssl(); }
#endif //EXT_ENABLE_OPENSSL

		/// rdbuf()->studown()
		/// в случае ошибки устанавливает failbit | badbit
		void shutdown();
		/// rdbuf()->close()
		/// в случае ошибки устанавливает failbit | badbit
		void close();
		/// rdbuf()->interrupt()
		void interrupt() noexcept;
		/// закрывает rdbuf()->close
		/// clear(std::ios::goodbit)
		void reset() noexcept;

	public:
		socket_stream();
		socket_stream(socket_streambuf && buf);
		explicit socket_stream(socket_handle_type sock_handle);

		socket_stream(const std::string & host, unsigned short port);
		socket_stream(const std::string & host, const std::string & service);

#if BOOST_OS_WINDOWS
		socket_stream(const std::wstring & host, unsigned short port);
		socket_stream(const std::wstring & host, const std::wstring & service);
#endif // BOOST_OS_WINDOWS

		socket_stream(const socket_stream &) = delete;
		socket_stream & operator =(const socket_stream &) = delete;

		socket_stream(socket_stream && right) noexcept;
		socket_stream & operator =(socket_stream && right) noexcept;

		void swap(socket_stream & right) noexcept;
	};

	inline void swap(socket_stream & s1, socket_stream & s2) noexcept
	{
		s1.swap(s2);
	}
}
