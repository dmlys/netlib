#pragma once
#include <memory>
#include <string>
#include <functional>
#include <streambuf>
#include <istream>

#include <ext/cppzlib.hpp>
#include <ext/iostreams/streambuf.hpp>
#include <ext/netlib/socket_stream.hpp>
#include <ext/netlib/http_parser.hpp>

namespace ext {
namespace netlib
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
		http_streambuf(std::streambuf & sb);
		http_streambuf(std::istream & is);
		http_streambuf(http_parser && parser, std::streambuf & sb);
		http_streambuf(http_parser && parser, std::istream & is);

		http_streambuf(http_streambuf &&) noexcept;
		http_streambuf & operator =(http_streambuf &&) noexcept;
	};


	class http_response_streambuf : public http_streambuf
	{
	public:
		int http_code() const { return m_parser.http_code(); }
		std::string http_status() const { return m_url_or_status; }

	public:
		using http_streambuf::http_streambuf;
	};


	class http_request_streambuf : public http_streambuf
	{
	public:
		std::string http_method() const { return m_parser.http_method(); }
		std::string http_url() const { return m_url_or_status; }

	public:
		using http_streambuf::http_streambuf;
	};


	/************************************************************************/
	/*              http_response_stream/http_request_stream                */
	/************************************************************************/
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

		http_response_stream(http_parser && parser, std::streambuf & sb)
			: std::istream(&m_streambuf), m_streambuf(std::move(parser), sb) {}

		http_response_stream(http_parser && parser, std::istream & is)
			: http_response_stream(std::move(parser), *is.rdbuf()) {}

		http_response_stream(http_response_stream && other) noexcept;
		http_response_stream & operator =(http_response_stream && other) noexcept;
	};

	class http_request_stream : public std::istream
	{
		http_request_streambuf m_streambuf;

	public:
		std::string http_method() const { return m_streambuf.http_method(); }
		std::string http_url() const { return m_streambuf.http_url(); }

	public:
		http_request_stream(std::streambuf & sb)
			: std::istream(&m_streambuf), m_streambuf(sb) {}

		http_request_stream(std::istream & is)
			: http_request_stream(*is.rdbuf()) {}

		http_request_stream(http_parser && parser, std::streambuf & sb)
			: std::istream(&m_streambuf), m_streambuf(std::move(parser), sb) {}

		http_request_stream(http_parser && parser, std::istream & is)
			: http_request_stream(std::move(parser), *is.rdbuf()) {}

		http_request_stream(http_request_stream  && other) noexcept;
		http_request_stream & operator =(http_request_stream  && other) noexcept;
	};
}}
