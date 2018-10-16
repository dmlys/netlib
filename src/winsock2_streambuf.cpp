// author: Dmitry Lysachenko
// date: Saturday 30 august 2015
// license: boost software license
//          http://www.boost.org/LICENSE_1_0.txt

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <codecvt>
#include <utility>

#include <ext/config.hpp>  // for EXT_UNREACHABLE
#include <ext/codecvt_conv.hpp>
#include <ext/Errors.hpp>  // for ext::FormatError

#include <ext/netlib/winsock2_streambuf.hpp>
#include <ext/netlib/socket_include.hpp>

#ifdef _MSC_VER
// warning C4244: '=' : conversion from '__int64' to 'long', possible loss of data
// warning C4244: 'initializing' : conversion from '__int64' to 'long', possible loss of data
// warning C4706: assignment within conditional expression
#pragma warning(disable : 4267 4244 4706)
#endif // _MSC_VER

namespace ext::netlib
{
	const std::string  winsock2_streambuf::empty_str;
	const std::wstring winsock2_streambuf::wempty_str;


	static void SockAddrToString(sockaddr * addr, int addrlen, std::string & out)
	{
		wchar_t buffer[INET6_ADDRSTRLEN];
		DWORD buflen = INET6_ADDRSTRLEN;
		int res = WSAAddressToStringW(addr, addrlen, nullptr, buffer, &buflen);
		if (res != 0)
			throw_last_socket_error("WSAAddressToStringW failed");

		buflen -= 1; out.clear();
		std::codecvt_utf8<wchar_t> cvt;
		ext::codecvt_convert::to_bytes(cvt, boost::make_iterator_range_n(buffer, buflen), out);
	}

	/************************************************************************/
	/*                   connect/resolve helpers                            */
	/************************************************************************/
	bool winsock2_streambuf::do_resolve(const wchar_t * host, const wchar_t * service, addrinfo_type ** result)
	{
		addrinfo_type hints;
		
		std::memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_socktype = SOCK_STREAM;

		int res = ::GetAddrInfoW(host, service, &hints, result);
		if (res == 0) return true;

		m_lasterror.assign(res, std::system_category());
		return false;
	}

	bool winsock2_streambuf::do_setnonblocking(handle_type sock)
	{
		unsigned long enabled = 1;
		int res = ::ioctlsocket(sock, FIONBIO, &enabled);
		if (res != 0) goto sockerror;
		return true;

	sockerror:
		m_lasterror.assign(::WSAGetLastError(), std::system_category());
		return false;
	}

	bool winsock2_streambuf::do_createsocket(handle_type & sock, const addrinfo_type * addr)
	{
		sock = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock != INVALID_SOCKET) return true;

		m_lasterror.assign(::WSAGetLastError(), std::system_category());
		return false;
	}

	inline bool winsock2_streambuf::do_sockshutdown(handle_type sock)
	{
		auto res = ::shutdown(sock, SD_BOTH);
		if (res == 0) return true;

		m_lasterror.assign(::WSAGetLastError(), std::system_category());
		return false;
	}

	bool winsock2_streambuf::do_sockclose(handle_type sock)
	{
		auto res = ::closesocket(sock);
		if (res == 0) return true;

		m_lasterror.assign(::WSAGetLastError(), std::system_category());
		return false;
	}

	bool winsock2_streambuf::do_sockconnect(handle_type sock, addrinfo_type * addr, unsigned short port)
	{
		auto * in = reinterpret_cast<sockaddr_in *>(addr->ai_addr);
		in->sin_port = ::htons(port);
		return do_sockconnect(sock, addr);
	}

	bool winsock2_streambuf::do_sockconnect(handle_type sock, const addrinfo_type * addr)
	{
		int wsaerr, res, solen;
		StateType prevstate;
		bool closesock, pubres; // в случае ошибки закрыть сокет
		auto until = time_point::clock::now() + m_timeout;
		
		prevstate = Closed;
		m_lasterror.clear();

		res = ::connect(sock, addr->ai_addr, addr->ai_addrlen);
		if (res == 0) goto connected; // connected immediately
		assert(res == SOCKET_ERROR);

		if ((wsaerr = ::WSAGetLastError()) != WSAEWOULDBLOCK)
			goto wsaerror;

	again:
		pubres = publish_connecting(sock);
		if (!pubres) goto intrreq;

		timeval timeout;
		make_timeval(until - time_point::clock::now(), timeout);

		fd_set write_set, err_set;
		FD_ZERO(&write_set);
		FD_ZERO(&err_set);
		FD_SET(sock, &write_set);
		FD_SET(sock, &err_set);

		prevstate = Connecting;
		res = ::select(0, nullptr, &write_set, &err_set, &timeout);
		if (res == 0) // timeout
		{
			wsaerr = WSAETIMEDOUT;
			goto wsaerror;
		}

		if (res == SOCKET_ERROR) goto sockerror;
		assert(res == 1);

		solen = sizeof(wsaerr);
		res = ::getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&wsaerr), &solen);
		if (res != 0)    goto sockerror;
		if (wsaerr != 0) goto wsaerror;
		
	connected:
		pubres = publish_opened(sock, prevstate);
		if (!pubres) goto intrreq;

		m_lasterror.clear();
		return true;

	sockerror:
		wsaerr = ::WSAGetLastError();
	wsaerror:
		pubres = m_state.compare_exchange_strong(prevstate, Closed, std::memory_order_relaxed);
		// произошла ошибка, она может результатом closesocket из interrupt
		// если мы успешно перешли в Closed - interrupt'а не было, а значит это обычная ошибка
		if (pubres)
		{
			if (wsaerr == WSAEINTR) goto again;
			
			closesock = true;
			if (wsaerr == WSAETIMEDOUT) m_lasterror = make_error_code(sock_errc::timeout);
			else                        m_lasterror.assign(wsaerr, std::system_category());
		}
		else intrreq:
		{
			// было прерывание, если оно было до publish_connecting, то мы должны закрыть сокет
			// иначе сокет был закрыт из interrupt
			m_lasterror = std::make_error_code(std::errc::interrupted);
			// такое возможно, только если мы не смогли опубликовать publish_connecting,
			closesock = prevstate == Closed;
		}

		if (closesock)
		{
			res = ::closesocket(sock);
			assert(res == 0 || (res = ::WSAGetLastError()) == 0);
		}

		m_sockhandle = INVALID_SOCKET;
		return false;
	}

	bool winsock2_streambuf::do_connect(const addrinfo_type * addr)
	{
		handle_type sock;
		for (; addr; addr = addr->ai_next)
		{
			// пытаемся создать сокет, если не получилось - это какая-то серьезная ошибка.
			// ::socket в MSDN https://msdn.microsoft.com/en-us/library/windows/desktop/ms740506%28v=vs.85%29.aspx
			// исключение WSAEAFNOSUPPORT, не поддерживаемый protocol family, в этом случае пробуем следующий адрес
			bool res = do_createsocket(sock, addr);
			if (!res)
			{
				if (m_lasterror == std::error_code(WSAEAFNOSUPPORT, std::system_category()))
					continue;
				else
					return false;
			}

			// выставляем non blocking режим. если не получилось - все очень плохо
			res = do_setnonblocking(sock);
			if (!res)
			{
				::closesocket(sock);
				return false;
			}

			// do_sockconnect публикует sock в m_sockhandle, а также учитывает interrupt сигналы.
			// в случае успеха:
			//   весь объект будет переведен в открытое состояние, вернет true
			// в случае ошибки или вызова interrupt:
			//   вернет false и гарантированно закроет sock, m_sockhandle == INVALID_SOCKET
			res = do_sockconnect(sock, addr);
			if (res)
			{
				init_buffers();
				return true;
			}

			// возможные коды ошибок для
			// ::connect в MSDN https://msdn.microsoft.com/en-us/library/windows/desktop/ms737625%28v=vs.85%29.aspx
			// в случае WSAECONNREFUSED, WSAENETUNREACH, WSAEHOSTUNREACH - имеет смысл попробовать след адрес
			
			auto & cat = m_lasterror.category();
			auto code = m_lasterror.value();

			bool try_next = cat == std::system_category() &&
				(code == WSAECONNREFUSED || code == WSAENETUNREACH || code == WSAEHOSTUNREACH);

			if (try_next)
				continue;
			else
				return false;
		}
		
		return false;
	}

	/************************************************************************/
	/*                     State methods                                    */
	/************************************************************************/
	bool winsock2_streambuf::publish_connecting(handle_type sock)
	{
		StateType prev = Closed;
		m_sockhandle = sock;
		return m_state.compare_exchange_strong(prev, Connecting, std::memory_order_release);
	}

	bool winsock2_streambuf::publish_opened(handle_type sock, StateType & expected)
	{
		// пытаемся переключится в Opened
		m_sockhandle = sock;
		return m_state.compare_exchange_strong(expected, Opened, std::memory_order_release);
	}

	bool winsock2_streambuf::do_shutdown()
	{
		StateType prev = Opened;
		bool success = m_state.compare_exchange_strong(prev, Shutdowned, std::memory_order_relaxed);
		if (success) return do_sockshutdown(m_sockhandle);

		// не получилось, значит был запрос на прерывание и shutdown был вызван оттуда
		// или же мы уже сделали shutdown ранее
		assert(prev == Interrupted || prev == Shutdowned);
		if (prev == Interrupted) m_lasterror = std::make_error_code(std::errc::interrupted);
		return false;
	}

	bool winsock2_streambuf::do_close()
	{
		StateType prev = m_state.exchange(Closed, std::memory_order_release);

#ifdef EXT_ENABLE_OPENSSL
		free_ssl();
#endif //EXT_ENABLE_OPENSSL

		auto sock = m_sockhandle;
		m_sockhandle = INVALID_SOCKET;

		// если мы были в Interrupting, тогда вызов interrupt закроет сокет
		if (prev == Interrupting) return true;
		return sock == INVALID_SOCKET ? true : do_sockclose(sock);
	}

	bool winsock2_streambuf::shutdown()
	{
		if (!is_open())
			return false;

		// try flush
		if (sync() == -1) return false;

#ifdef EXT_ENABLE_OPENSSL
		// try stop ssl
		if (!stop_ssl()) return false;
#endif //EXT_ENABLE_OPENSSL

		// делаем shutdown
		return do_shutdown();
	}

	bool winsock2_streambuf::close()
	{
		bool result;
		if (!is_open())
			result = do_close();
		else
		{
			// делаем shutdown, после чего в любом случае закрываем сокет
			result = shutdown();
			result &= do_close();
		}

		// если закрытие успешно, очищаем последнюю ошибку
		if (result) m_lasterror.clear();
		return result;
	}

	void winsock2_streambuf::interrupt()
	{
		int res;
		StateType prev;
		handle_type sock;
		//bool success;

		prev = m_state.load(std::memory_order_acquire);
		do switch(prev)
		{
			/// если мы уже прерваны или прерываемся - просто выходим
			case Interrupted:
			case Interrupting: return;
			/// иначе пытаемся перейти в Interrupting
			default:
				sock = m_sockhandle;

		} while (!m_state.compare_exchange_weak(prev, Interrupting, std::memory_order_acquire, std::memory_order_relaxed));
		
		// ok, перешли
		auto state = prev;
		prev = Interrupting;

		switch (state)
		{
			case Interrupting:
			case Interrupted:
			default:
				EXT_UNREACHABLE(); // сюда мы попасть не должны по определению

			case Closed:
			case Shutdowned:
				m_state.compare_exchange_strong(prev, Interrupted, std::memory_order_relaxed);
				return; // в данном состояние сокет не ожидается в блокирующих состояниях -
				        // никаких доп действий не требуется. Но состояние перекинуто в Interrupted.
			
			case Connecting:
				// состояние подключения, это значит что есть поток внутри класса и он на некоей стадии подключения.
				// В идеале хотелось бы сделать shutdown,
				// но по факту в winsock2 обмен пакетами подключения начинается не мгновенно,
				// а с некоторой задержкой, при этом вызов shutdown вернет ошибку.
				// Как в дальнейшем будет вести себя select - не понятно, поэтому просто делаем closesocket
				assert(sock != INVALID_SOCKET);
				res = ::closesocket(sock);
				assert(res == 0 || (res = ::WSAGetLastError()) == 0);

				m_state.compare_exchange_strong(prev, Interrupted, std::memory_order_relaxed);
				return;
		
			case Opened:
				// нормальный режим работы, сокет открыт, и потенциально есть блокирующий вызов: recv/send
				assert(sock != INVALID_SOCKET);
				res = ::shutdown(sock, SD_BOTH);
				assert(res == 0);

				bool success = m_state.compare_exchange_strong(prev, Interrupted, std::memory_order_relaxed);
				if (success) return;

				// пока мы shutdown'лись, был запрос на закрытие класса из основного потока,
				// он же видя что мы в процессе interrupt'а не стал делать закрытие сокета, а оставил это нам
				assert(prev == Closed);
				assert(sock != INVALID_SOCKET);
				res = ::closesocket(sock);
				assert(res == 0 || (res = ::WSAGetLastError()) == 0);
				return;
		}
	}

	void winsock2_streambuf::init_handle(handle_type sock)
	{
		StateType prev;
		bool pubres;

		if (is_open())
		{
			m_lasterror = std::make_error_code(std::errc::already_connected);
			goto error;
		}

		if (not do_setnonblocking(sock))
			goto error;

		// пытаемся опубликовать сокет, возможен interrupt
		m_sockhandle = sock;
		prev = Closed;
		pubres = m_state.compare_exchange_strong(prev, Opened, std::memory_order_release);
		if (pubres)
		{
			init_buffers();
			return;
		}

	//interrupted:
		m_lasterror = std::make_error_code(std::errc::interrupted);
	error:
		// нас interrupt'нули - выставляем соотвествующий код ошибки
		int code = m_lasterror.value();
		if (m_lasterror.category() != std::generic_category() || (code != EBADF and code != ENOTSOCK))
			::closesocket(sock);

		throw std::system_error(m_lasterror, "winsock2_streambuf::init_handle failed");
	}

	/************************************************************************/
	/*                   read/write/others                                  */
	/************************************************************************/
	bool winsock2_streambuf::is_valid() const
	{
		return m_sockhandle != INVALID_SOCKET && !m_lasterror;
	}

	bool winsock2_streambuf::is_open() const
	{
		return m_sockhandle != INVALID_SOCKET;
	}

	bool winsock2_streambuf::wait_state(time_point until, int fstate)
	{
		int wsaerr;
		int solen;

	again:
		struct timeval timeout;
		make_timeval(until - time_point::clock::now(), timeout);

		fd_set read_set, write_set, err_set;
		fd_set * pread_set = nullptr;
		fd_set * pwrite_set = nullptr;

		if (fstate & readable)
		{
			pread_set = &read_set;
			FD_ZERO(pread_set);
			FD_SET(m_sockhandle, pread_set);
		}

		if (fstate & writable)
		{
			pwrite_set = &write_set;
			FD_ZERO(pwrite_set);
			FD_SET(m_sockhandle, pwrite_set);
		}
		
		FD_ZERO(&err_set);
		FD_SET(m_sockhandle, &err_set);

		int res = ::select(m_sockhandle + 1, pread_set, pwrite_set, &err_set, &timeout);
		if (res == 0) // timeout
		{
			m_lasterror = make_error_code(sock_errc::timeout);
			return false;
		}

		if (res == -1) goto sockerror;
		assert(res >= 1);

		solen = sizeof(wsaerr);
		res = ::getsockopt(m_sockhandle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&wsaerr), &solen);
		if (res != 0)    goto sockerror;
		if (wsaerr != 0) goto wsaerror;

		return true;

	sockerror:
		wsaerr = ::WSAGetLastError();
	wsaerror:
		if (rw_error(-1, wsaerr, m_lasterror)) return false;
		goto again;
	}

	std::streamsize winsock2_streambuf::showmanyc()
	{
		//if (!is_valid()) return 0;

#ifdef EXT_ENABLE_OPENSSL
		if (ssl_started())
		{
			return ::SSL_pending(m_sslhandle);
		}
#endif //EXT_ENABLE_OPENSSL

		unsigned long avail = 0;
		auto res = ::ioctlsocket(m_sockhandle, FIONREAD, &avail);
		return res == 0 ? avail : 0;
	}

	std::size_t winsock2_streambuf::read_some(char_type * data, std::size_t count)
	{
		//if (!is_valid()) return 0;
		auto until = time_point::clock::now() + m_timeout;
		do {

#ifdef EXT_ENABLE_OPENSSL
			if (ssl_started())
			{
				int res = ::SSL_read(m_sslhandle, data, count);
				if (res > 0) return res;

				if (ssl_rw_error(res, m_lasterror)) return 0;
				continue;
			}
#endif // EXT_ENABLE_OPENSSL

			int res = ::recv(m_sockhandle, data, count, 0);
			if (res > 0) return res;

			if (rw_error(res, ::WSAGetLastError(), m_lasterror)) return 0;
			continue;

		} while (wait_readable(until));
		return 0;
	}

	std::size_t winsock2_streambuf::write_some(const char_type * data, std::size_t count)
	{
		//if (!is_valid()) return 0;
		auto until = time_point::clock::now() + m_timeout;
		do {

#ifdef EXT_ENABLE_OPENSSL
			if (ssl_started())
			{
				int res = ::SSL_write(m_sslhandle, data, count);
				if (res > 0) return res;

				if (ssl_rw_error(res, m_lasterror)) return 0;
				continue;
			}
#endif // EXT_ENABLE_OPENSSL

			int res = ::send(m_sockhandle, data, count, 0);
			if (res > 0) return res;

			if (rw_error(res, ::WSAGetLastError(), m_lasterror)) return 0;
			continue;

		} while (wait_readable(until));
		return 0;
	}

	bool winsock2_streambuf::rw_error(int res, int err, error_code_type & err_code)
	{
		// error can be result of shutdown from interrupt
		auto state = m_state.load(std::memory_order_relaxed);
		if (state >= Interrupting)
		{
			err_code = std::make_error_code(std::errc::interrupted);
			return true;
		}

		// it was eof
		if (res >= 0)
		{
			err_code = make_error_code(sock_errc::eof);
			return true;
		}

		// when using nonblocking socket, EWOULDBLOCK mean repeat operation later,
		if (err == WSAEINTR || err == WSAEWOULDBLOCK) return false;

		err_code.assign(err, std::system_category());
		return true;
	}

	/************************************************************************/
	/*                   actual connect                                     */
	/************************************************************************/
	bool winsock2_streambuf::connect(const addrinfo_type & addr)
	{
		assert(&addr);
		if (is_open())
		{
			m_lasterror = std::make_error_code(std::errc::already_connected);
			return false;
		}
		
		return do_connect(&addr);
	}

	bool winsock2_streambuf::connect(const std::wstring & host, const std::wstring & service)
	{
		if (is_open())
		{
			m_lasterror = std::make_error_code(std::errc::already_connected);
			return false;
		}

		addrinfo_type * addr = nullptr;
		bool res = do_resolve(host.c_str(), service.c_str(), &addr);
		if (!res) return false;

		assert(addr);
		res = do_connect(addr);

		FreeAddrInfo(addr);
		return res;
	}

	bool winsock2_streambuf::connect(const std::wstring & host, unsigned short port)
	{
		if (is_open())
		{
			m_lasterror = std::make_error_code(std::errc::already_connected);
			return false;
		}

		addrinfo_type * addr = nullptr;
		bool res = do_resolve(host.c_str(), nullptr, &addr);
		if (!res) return false;
		
		set_port(addr, port);
		res = do_connect(addr);
		
		FreeAddrInfo(addr);
		return res;
	}

	bool winsock2_streambuf::connect(const std::string & host, const std::string & service)
	{
		std::codecvt_utf8<wchar_t> cvt;
		auto whost = ext::codecvt_convert::from_bytes(cvt, host);
		auto wservice = ext::codecvt_convert::from_bytes(cvt, service);
		return connect(whost, wservice);
	}

	bool winsock2_streambuf::connect(const std::string & host, unsigned short port)
	{
		std::codecvt_utf8<wchar_t> cvt;
		auto whost = ext::codecvt_convert::from_bytes(cvt, host);
		return connect(whost, port);
	}

	/************************************************************************/
	/*                     ssl stuff                                        */
	/************************************************************************/
#ifdef EXT_ENABLE_OPENSSL
	static int fstate_from_ssl_result(int result)
	{
		if      (result == SSL_ERROR_WANT_READ)  return winsock2_streambuf::readable;
		else if (result == SSL_ERROR_WANT_WRITE) return winsock2_streambuf::writable;
		else        /* ??? */                    return winsock2_streambuf::readable | winsock2_streambuf::writable;
	}

	bool winsock2_streambuf::ssl_started() const
	{
		return m_sslhandle != nullptr && ::SSL_get_session(m_sslhandle) != nullptr;
	}

	winsock2_streambuf::error_code_type winsock2_streambuf::ssl_error(SSL * ssl, int error)
	{
		int ssl_err = ::SSL_get_error(ssl, error);
		return openssl_geterror(ssl_err);
	}

	bool winsock2_streambuf::ssl_rw_error(int & res, error_code_type & err_code)
	{
		int wsaerr;
		int ret = res;

		// error can be result of shutdown from interrupt
		auto state = m_state.load(std::memory_order_relaxed);
		if (state >= Interrupting)
		{
			err_code = std::make_error_code(std::errc::interrupted);
			return true;
		}

		res = ::SSL_get_error(m_sslhandle, ret);
		switch (res)
		{
			// if it's SSL_ERROR_WANT_{WRITE,READ}
			// WSAGetLastError() can be WSAEWOULDBLOCK or WSAEINTR - repeat operation
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				return false;

				// can this happen? just try to handle as SSL_ERROR_SYSCALL
				// according to doc, this can happen if res > 0
			case SSL_ERROR_NONE:

			case SSL_ERROR_SSL:
			case SSL_ERROR_SYSCALL:
				// if it some generic SSL error
				if ((wsaerr = ::ERR_get_error()))
				{
					err_code.assign(wsaerr, openssl_err_category());
					return true;
				}

				if ((wsaerr = ::WSAGetLastError()))
				{
					// when using nonblocking socket, EWOULDBLOCK mean repeat operation later,
					if (wsaerr == WSAEINTR || wsaerr == WSAEWOULDBLOCK) return false;

					err_code.assign(wsaerr, std::system_category());
					return true;
				}

				// it was unexpected eof
				if (ret == 0)
				{
					err_code = make_error_code(sock_errc::eof);
					return true;
				}

			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_WANT_X509_LOOKUP:
			case SSL_ERROR_WANT_CONNECT:
			case SSL_ERROR_WANT_ACCEPT:
			default:
				err_code.assign(res, openssl_ssl_category());
				return true;
		}

	}

	bool winsock2_streambuf::do_createssl(SSL *& ssl, SSL_CTX * sslctx)
	{
		ssl = ::SSL_new(sslctx);
		if (ssl) return true;

		m_lasterror.assign(::ERR_get_error(), openssl_err_category());
		return false;
	}

	bool winsock2_streambuf::do_configuressl(SSL *& ssl, const char * servername)
	{
		int res;
		if (servername && *servername != 0) // not empty
		{
			res = ::SSL_set_tlsext_host_name(ssl, servername);
			if (res != 1) goto error;
		}

		::SSL_set_mode(ssl, ::SSL_get_mode(ssl) | SSL_MODE_AUTO_RETRY);
		return true;

	error:
		m_lasterror = ssl_error(ssl, res);
		::SSL_free(ssl);
		ssl = nullptr;
		return false;
	}

	bool winsock2_streambuf::do_sslconnect(SSL * ssl)
	{
		int res = ::SSL_set_fd(ssl, m_sockhandle);
		if (res <= 0)
		{
			m_lasterror = ssl_error(ssl, res);
			return false;
		}

		auto until = time_point::clock::now() + m_timeout;
		int fstate;

		do {
			res = ::SSL_connect(ssl);
			if (res > 0) return true;

			if (ssl_rw_error(res, m_lasterror)) return false;
			
			fstate = fstate_from_ssl_result(res);
		} while (wait_state(until, fstate));
		return false;
	}

	bool winsock2_streambuf::do_sslaccept(SSL * ssl)
	{
		int res = ::SSL_set_fd(ssl, m_sockhandle);
		if (res <= 0)
		{
			m_lasterror = ssl_error(ssl, res);
			return false;
		}

		auto until = time_point::clock::now() + m_timeout;
		int fstate;

		do {
			res = ::SSL_accept(ssl);
			if (res > 0) return true;

			if (ssl_rw_error(res, m_lasterror)) return false;

			fstate = fstate_from_ssl_result(res);
		} while (wait_state(until, fstate));

		return false;
	}

	bool winsock2_streambuf::do_sslshutdown(SSL * ssl)
	{
		// смотри описание 2х фазного SSL_shutdown в описании функции SSL_shutdown:
		// https://www.openssl.org/docs/manmaster/ssl/SSL_shutdown.html
		
		char ch;
		int res, fstate, selres;
		long int rc;
		handle_type sock;
		fd_set rdset;

		auto until = time_point::clock::now() + m_timeout;
		TIMEVAL tv = {0, 0};

		// first shutdown
		do {
			res = ::SSL_shutdown(ssl);
			if (res > 0) goto success;

			// should attempt second shutdown
			if (res == 0) break;
			
			if (ssl_rw_error(res, m_lasterror)) return false;

			fstate = fstate_from_ssl_result(res);
		} while (wait_state(until, fstate));
		
		// second shutdown
		do {
			res = ::SSL_shutdown(ssl);
			assert(res != 0);
			if (res > 0) goto success;

			if (ssl_rw_error(res, m_lasterror)) break;

			fstate = fstate_from_ssl_result(res);
		} while (wait_state(until, fstate));
		
		// второй shutdown не получился, это может быть как ошибка,
		// так и нам просто закрыли канал по shutdown на другой стороне. проверяем
		sock = ::SSL_get_fd(ssl);
		FD_ZERO(&rdset);
		FD_SET(sock, &rdset);

		selres = select(0, &rdset, nullptr, nullptr, &tv);
		if (selres <= 0) return false;

		rc = recv(sock, &ch, 1, MSG_PEEK);
		if (rc != 0) return false; // socket closed

		// да мы действительно получили FD_CLOSE
		m_lasterror.clear();

	success:
		res = ::SSL_clear(ssl);
		if (res > 0) return true;

		// -1 - error or nonblocking, we are always blocking
		m_lasterror = ssl_error(ssl, res);
		return false;
	}

	void winsock2_streambuf::set_ssl(SSL * ssl)
	{
		if (ssl_started())
			throw std::logic_error("winsock2_streambuf: can't set_ssl, ssl already started");

		free_ssl();
		m_sslhandle = ssl;
	}

	bool winsock2_streambuf::start_ssl(SSL_CTX * sslctx)
	{
		if (!is_open())
		{
			m_lasterror.assign(WSAENOTSOCK, std::system_category());
			return false;
		}

		if (m_sslhandle)
		{
			::SSL_set_SSL_CTX(m_sslhandle, sslctx);
			return do_sslconnect(m_sslhandle);
		}
		else
		{
			return do_createssl(m_sslhandle, sslctx) &&
			       do_configuressl(m_sslhandle) &&
			       do_sslconnect(m_sslhandle);
		}
	}

	bool winsock2_streambuf::start_ssl(const SSL_METHOD * sslmethod, const std::string & servername)
	{
		if (!is_open())
		{
			m_lasterror.assign(WSAENOTSOCK, std::system_category());
			return false;
		}

		if (sslmethod == nullptr)
			sslmethod = ::SSLv23_client_method();

		SSL_CTX * sslctx = ::SSL_CTX_new(sslmethod);
		if (sslctx == nullptr)
		{
			m_lasterror.assign(::ERR_get_error(), openssl_err_category());
			return false;
		}
		
		bool result;
		if (m_sslhandle)
		{
			::SSL_set_SSL_CTX(m_sslhandle, sslctx);
			result = do_configuressl(m_sslhandle, servername.c_str());
		}
		else
		{
			result = do_createssl(m_sslhandle, sslctx) &&
			         do_configuressl(m_sslhandle, servername.c_str());
		}
		
		::SSL_CTX_free(sslctx);
		return result && do_sslconnect(m_sslhandle);
	}

	bool winsock2_streambuf::start_ssl(const SSL_METHOD * sslmethod, const std::wstring & wservername)
	{
		std::codecvt_utf8<wchar_t> cvt;
		auto servername = ext::codecvt_convert::to_bytes(cvt, wservername);
		return start_ssl(sslmethod, servername);
	}

	bool winsock2_streambuf::start_ssl()
	{
		if (m_sslhandle)
			return do_sslconnect(m_sslhandle);
		else
		{
			const SSL_METHOD * sslm = nullptr;
			return start_ssl(sslm);
		}
	}

	bool winsock2_streambuf::accept_ssl(SSL_CTX * sslctx)
	{
		if (!is_open())
		{
			m_lasterror.assign(ENOTSOCK, std::system_category());
			return false;
		}

		bool result;
		if (m_sslhandle)
		{
			::SSL_set_SSL_CTX(m_sslhandle, sslctx);
			result = do_configuressl(m_sslhandle);
		}
		else
		{
			result = do_createssl(m_sslhandle, sslctx) &&
			         do_configuressl(m_sslhandle);
		}

		return result && do_sslaccept(m_sslhandle);
	}

	bool winsock2_streambuf::stop_ssl()
	{
		if (!ssl_started()) return true;

		// flush failed
		if (sync() == -1) return false;
		return do_sslshutdown(m_sslhandle);
	}

	void winsock2_streambuf::free_ssl()
	{
		::SSL_free(m_sslhandle);
		m_sslhandle = nullptr;
	}

#endif //EXT_ENABLE_OPENSSL

	/************************************************************************/
	/*                     getters/setters                                  */
	/************************************************************************/
	winsock2_streambuf::duration_type winsock2_streambuf::timeout(duration_type newtimeout)
	{
		if (newtimeout < std::chrono::seconds(1))
			newtimeout = std::chrono::seconds(1);
		
		return std::exchange(m_timeout, newtimeout);
	}

	void winsock2_streambuf::getpeername(sockaddr_type * addr, int * addrlen)
	{
		if (!is_open())
			throw std::runtime_error("winsock2_streambuf::getpeername: bad socket");

		auto res = ::getpeername(m_sockhandle, addr, addrlen);
		if (res != 0)
		{
			throw_last_socket_error("winsock2_streambuf::peer_name getpeername failed");
		}
	}

	void winsock2_streambuf::getsockname(sockaddr_type * addr, int * addrlen)
	{
		if (!is_open())
			throw std::runtime_error("winsock2_streambuf::getsockname: bad socket");

		auto res = ::getsockname(m_sockhandle, addr, addrlen);
		if (res != 0)
		{
			throw_last_socket_error("winsock2_streambuf::sock_name getsockname failed");
		}
	}

	std::string winsock2_streambuf::peer_endpoint()
	{
		sockaddr_storage addrstore;
		int addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getpeername(addr, &addrlen);

		std::string res;
		SockAddrToString(addr, addrlen, res);
		return res;
	}

	std::string winsock2_streambuf::sock_endpoint()
	{
		sockaddr_storage addrstore;
		int addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		std::string res;
		SockAddrToString(addr, addrlen, res);
		return res;
	}

	unsigned short winsock2_streambuf::peer_port()
	{
		sockaddr_storage addrstore;
		int addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getpeername(addr, &addrlen);

		// in winsock2 both sockaddr_in6 and sockaddr_in have port member on same offset
		auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
		return ::ntohs(port);
	}

	unsigned short winsock2_streambuf::sock_port()
	{
		sockaddr_storage addrstore;
		int addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		// in winsock2 both sockaddr_in6 and sockaddr_in have port member on same offset
		auto port = reinterpret_cast<sockaddr_in6 *>(addr)->sin6_port;
		return ::ntohs(port);
	}

	void winsock2_streambuf::peer_name(std::string & name, unsigned short & port)
	{
		sockaddr_storage addrstore;
		int addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getpeername(addr, &addrlen);

		inet_ntop(addr, name, port);
	}

	void winsock2_streambuf::sock_name(std::string & name, unsigned short & port)
	{
		sockaddr_storage addrstore;
		int addrlen = sizeof(addrstore);
		auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
		getsockname(addr, &addrlen);

		inet_ntop(addr, name, port);
	}

	auto winsock2_streambuf::peer_name() -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		peer_name(res.first, res.second);
		return res;
	}

	auto winsock2_streambuf::sock_name() -> std::pair<std::string, unsigned short>
	{
		std::pair<std::string, unsigned short> res;
		sock_name(res.first, res.second);
		return res;
	}

	std::string winsock2_streambuf::peer_address()
	{
		std::string addr; unsigned short port;
		peer_name(addr, port);
		return addr;
	}

	std::string winsock2_streambuf::sock_address()
	{
		std::string addr; unsigned short port;
		sock_name(addr, port);
		return addr;
	}

	/************************************************************************/
	/*                   ctors/dtor                                         */
	/************************************************************************/
	winsock2_streambuf::winsock2_streambuf()
	{
		m_sockhandle = INVALID_SOCKET;
	}

	winsock2_streambuf::~winsock2_streambuf()
	{
		close();
	}

	winsock2_streambuf::winsock2_streambuf(socket_handle_type sock_handle)
	{
		if (not do_setnonblocking(sock_handle))
		{
			int code = m_lasterror.value();
			if (m_lasterror.category() != std::generic_category() || (code != EBADF && code != ENOTCONN))
				::closesocket(sock_handle);

			throw std::system_error(m_lasterror, "winsock2_streambuf::setnonblocking failed");
		}

		m_sockhandle = sock_handle;
		m_state.store(Opened, std::memory_order_relaxed);
		init_buffers();
	}

	winsock2_streambuf::winsock2_streambuf(winsock2_streambuf && right) noexcept
		: base_type(std::move(right)),
	      m_sockhandle(std::exchange(right.m_sockhandle, INVALID_SOCKET)),
#ifdef EXT_ENABLE_OPENSSL
		  m_sslhandle(std::exchange(right.m_sslhandle, nullptr)),
#endif
		  m_state(right.m_state.exchange(Closed, std::memory_order_relaxed)),
		  m_lasterror(std::exchange(right.m_lasterror, error_code_type {})),
		  m_timeout(right.m_timeout)
	{

	}

	winsock2_streambuf & winsock2_streambuf::operator=(winsock2_streambuf && right) noexcept
	{
		if (this != &right)
		{
			close();

			base_type::operator =(std::move(right));
			m_sockhandle = std::exchange(right.m_sockhandle, INVALID_SOCKET);
#ifdef EXT_ENABLE_OPENSSL
			m_sslhandle = std::exchange(right.m_sslhandle, nullptr);
#endif
			m_state.store(right.m_state.exchange(Closed, std::memory_order_relaxed), std::memory_order_relaxed);
			m_lasterror = std::exchange(right.m_lasterror, error_code_type {});
			m_timeout = right.m_timeout;
		}

		return *this;
	}

	void winsock2_streambuf::swap(winsock2_streambuf & other) noexcept
	{
		using std::swap;

		auto tmp = std::move(other);
		other = std::move(*this);
		*this = std::move(tmp);
	}
} // namespace ext::netlib
