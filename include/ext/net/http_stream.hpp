#pragma once
#include <memory>
#include <string>
#include <functional>
#include <streambuf>
#include <istream>

#include <ext/cppzlib.hpp>
#include <ext/iostreams/streambuf.hpp>
#include <ext/net/socket_stream.hpp>
#include <ext/net/http_parser.hpp>

namespace ext::net
{
	/************************************************************************/
	/*                       http_streambuf                                 */
	/************************************************************************/
	class http_streambuf : public ext::streambuf
	{
	protected:
		http_parser m_parser;
		std::streambuf * m_source;
		int_type (http_streambuf::*m_reader)();

		std::unique_ptr<char[]> m_buffer;
		std::size_t m_buffer_size = 1024;
		std::string m_url_or_status;

#ifdef EXT_ENABLE_CPPZLIB
		zlib::inflate_stream m_inflator {MAX_WBITS + 32};
#endif
		
	protected:
		void init();
		int_type underflow() override;
		int_type underflow_normal();
		int_type underflow_deflated();

	public:
		      http_parser & parser()       noexcept { return m_parser; }
		const http_parser & parser() const noexcept { return m_parser; }

	public:
		http_streambuf(std::streambuf & sb);
		http_streambuf(std::istream & is);
		http_streambuf(http_parser && parser, std::streambuf & sb);
		http_streambuf(http_parser && parser, std::istream & is);

		http_streambuf(http_streambuf &&) noexcept;
		http_streambuf & operator =(http_streambuf &&) noexcept;
	};

	/************************************************************************/
	/*              http_response_stream/http_request_stream                */
	/************************************************************************/
	class http_stream : public std::istream
	{
		http_streambuf m_streambuf;

	public:
		      http_parser & parser()       noexcept { return m_streambuf.parser(); }
		const http_parser & parser() const noexcept { return m_streambuf.parser(); }

	public:
		http_stream(std::streambuf & sb)
			: std::istream(&m_streambuf), m_streambuf(sb) {}

		http_stream(std::istream & is)
			: http_stream(*is.rdbuf()) {}

		http_stream(http_parser && parser, std::streambuf & sb)
			: std::istream(&m_streambuf), m_streambuf(std::move(parser), sb) {}

		http_stream(http_parser && parser, std::istream & is)
			: http_stream(std::move(parser), *is.rdbuf()) {}

		http_stream(http_stream && other) noexcept;
		http_stream & operator =(http_stream && other) noexcept;
	};
}
