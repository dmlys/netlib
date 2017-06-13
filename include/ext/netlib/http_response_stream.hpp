#pragma once
#include <memory>
#include <string>
#include <functional>
#include <streambuf>
#include <istream>

#include <ext/cppzlib.hpp>
#include <ext/iostreams/streambuf.hpp>
#include <ext/netlib/socket_stream.hpp>
#include <ext/netlib/http_response_parser.hpp>

namespace ext {
namespace netlib
{
	class http_response_streambuf : public ext::streambuf
	{
		http_response_parser m_parser;
		std::streambuf * m_source;
		int_type (http_response_streambuf::*m_reader)();

		std::unique_ptr<char[]> m_buffer;
		std::size_t m_buffer_size = 1024;

#ifdef EXT_ENABLE_CPPZLIB
		zlib::inflate_stream m_inflator {MAX_WBITS + 32};
#endif
		
	protected:
		void init();
		int_type underflow() override;
		int_type underflow_normal();
		int_type underflow_deflated();

	public:
		int http_code() const { return m_parser.http_code(); }

	public:
		http_response_streambuf(std::streambuf & sb);
		http_response_streambuf(std::istream & is);
		http_response_streambuf(http_response_parser && parser, std::streambuf & sb);
		http_response_streambuf(http_response_parser && parser, std::istream & is);

		http_response_streambuf(http_response_streambuf &&) noexcept;
		http_response_streambuf & operator =(http_response_streambuf &&) noexcept;
	};


	class http_response_stream : public std::istream
	{
		http_response_streambuf m_streambuf;

	public:
		int http_code() const { return m_streambuf.http_code(); }

	public:
		http_response_stream(std::streambuf & sb)
			: std::istream(&m_streambuf), m_streambuf(sb) {}

		http_response_stream(std::istream & is)
			: http_response_stream(*is.rdbuf()) {}

		http_response_stream(http_response_parser && parser, std::streambuf & sb)
			: std::istream(&m_streambuf), m_streambuf(std::move(parser), sb) {}

		http_response_stream(http_response_parser && parser, std::istream & is)
			: http_response_stream(std::move(parser), *is.rdbuf()) {}

		http_response_stream(http_response_stream && other) noexcept;
		http_response_stream & operator =(http_response_stream && other) noexcept;
	};
}}
