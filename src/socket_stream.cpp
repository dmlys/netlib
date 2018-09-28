#include <ext/netlib/socket_stream.hpp>

namespace ext::netlib
{
#if BOOST_OS_WINDOWS
	void socket_stream::connect(const std::wstring & host, unsigned short port)
	{
		if (m_streambuf.connect(host, port))
			clear();
		else
			setstate(std::ios::failbit);
	}

	void socket_stream::connect(const std::wstring & host, const std::wstring & service)
	{
		if (m_streambuf.connect(host, service))
			clear();
		else
			setstate(std::ios::failbit);
	}
#endif // BOOST_OS_WINDOWS

	void socket_stream::connect(const std::string & host, unsigned short port)
	{
		if (m_streambuf.connect(host, port))
			clear();
		else
			setstate(std::ios::failbit);
	}

	void socket_stream::connect(const std::string & host, const std::string & service)
	{
		if (m_streambuf.connect(host, service))
			clear();
		else
			setstate(std::ios::failbit);
	}

#ifdef EXT_ENABLE_OPENSSL
	void socket_stream::start_ssl()
	{
		if (fail()) return;

		if (!m_streambuf.start_ssl())
			setstate(std::ios::badbit | std::ios::failbit);
	}

	void socket_stream::start_ssl(SSL_CTX * sslctx)
	{
		if (fail()) return;

		if (!m_streambuf.start_ssl(sslctx))
			setstate(std::ios::badbit | std::ios::failbit);
	}

	void socket_stream::start_ssl(const SSL_METHOD * sslmethod)
	{
		if (fail()) return;

		if (!m_streambuf.start_ssl(sslmethod))
			setstate(std::ios::badbit | std::ios::failbit);
	}

	void socket_stream::start_ssl(const std::string & servername)
	{
		if (fail()) return;

		if (!m_streambuf.start_ssl(servername))
			setstate(std::ios::badbit | std::ios::failbit);
	}

	void socket_stream::start_ssl(const SSL_METHOD * sslmethod, const std::string & servername)
	{
		if (fail()) return;

		if (!m_streambuf.start_ssl(sslmethod, servername))
			setstate(std::ios::badbit | std::ios::failbit);
	}

#if BOOST_OS_WINDOWS
	void socket_stream::start_ssl(const SSL_METHOD * sslmethod, const std::wstring & wservername)
	{
		if (fail()) return;

		if (!m_streambuf.start_ssl(sslmethod, wservername))
			setstate(std::ios::badbit | std::ios::failbit);
	}

	void socket_stream::start_ssl(const std::wstring & wservername)
	{
		if (fail()) return;

		if (!m_streambuf.start_ssl(wservername))
			setstate(std::ios::badbit | std::ios::failbit);
	}
#endif // BOOST_OS_WINDOWS

	void socket_stream::accept_ssl(SSL_CTX * sslctx)
	{
		if (fail()) return;

		if (!m_streambuf.accept_ssl(sslctx))
			setstate(std::ios::badbit | std::ios::failbit);
	}

	void socket_stream::stop_ssl()
	{
		if (fail()) return;

		if (!m_streambuf.stop_ssl())
			setstate(std::ios::failbit | std::ios::badbit);
	}
#endif // EXT_ENABLE_OPENSSL
	void socket_stream::shutdown()
	{
		if (fail()) return;

		if (!m_streambuf.shutdown())
			setstate(std::ios::failbit | std::ios::badbit);
	}

	void socket_stream::close()
	{
		if (fail()) return;

		if (!m_streambuf.close())
			setstate(std::ios::failbit | std::ios::badbit);
	}

	void socket_stream::interrupt()
	{
		m_streambuf.interrupt();
	}

	void socket_stream::reset()
	{
		m_streambuf.close();
		clear(std::ios::goodbit);
	}

	socket_stream::socket_stream()
	    : std::iostream(&m_streambuf)
	{

	}

	socket_stream::socket_stream(socket_handle_type sock_handle)
	    : std::iostream(&m_streambuf), m_streambuf(sock_handle)
	{

	}

	socket_stream::socket_stream(socket_streambuf && buf)
	    : std::iostream(&m_streambuf), m_streambuf(std::move(buf))
	{

	}

#if BOOST_OS_WINDOWS
	socket_stream::socket_stream(const std::wstring & host, unsigned short port)
	    : std::iostream(&m_streambuf)
	{
		connect(host, port);
	}

	socket_stream::socket_stream(const std::wstring & host, const std::wstring & service)
	    : std::iostream(&m_streambuf)
	{
		connect(host, service);
	}
#endif // BOOST_OS_WINDOWS

	socket_stream::socket_stream(const std::string & host, unsigned short port)
	    : std::iostream(&m_streambuf)
	{
		connect(host, port);
	}

	socket_stream::socket_stream(const std::string & host, const std::string & service)
	    : std::iostream(&m_streambuf)
	{
		connect(host, service);
	}

	socket_stream::socket_stream(socket_stream && op) noexcept
	    : std::iostream(std::move(op)),
	      m_streambuf(std::move(op.m_streambuf))
	{
		set_rdbuf(&m_streambuf);
	};

	socket_stream & socket_stream::operator =(socket_stream && op) noexcept
	{
		if (this != &op)
		{
			this->std::iostream::operator= (std::move(op));
			m_streambuf = std::move(op.m_streambuf);
		}

		return *this;
	}

	void socket_stream::swap(socket_stream & op) noexcept
	{
		this->std::iostream::swap(op);
		m_streambuf.swap(op.m_streambuf);
	}
}
