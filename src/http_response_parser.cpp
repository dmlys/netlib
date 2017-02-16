#include <cassert>
#include <ext/range.hpp>
#include <ext/cppzlib.hpp>
#include <ext/iostreams/streambuf.hpp>
#include <ext/netlib/http_response_parser.hpp>

namespace ext {
namespace netlib
{
	BOOST_NORETURN void http_response_parser::throw_parser_error(const http_parser * parser)
	{
		auto * errmsg = http_errno_description(HTTP_PARSER_ERRNO(parser));

		std::string msg = "http_parser error: ";
		msg += errmsg;

		throw std::runtime_error(std::move(msg));
	}

	BOOST_NORETURN void http_response_parser::throw_stream_error()
	{
		throw std::ios::failure("http_response_parser: stream read failure");
	}

	void http_response_parser::init_parser(http_parser * parser, http_parser_settings * settings)
	{
		http_parser_settings_init(settings);

		settings->on_message_complete = &on_message_complete;
		settings->on_header_field     = &on_header_field;
		settings->on_header_value     = &on_header_value;
		settings->on_headers_complete = &on_headers_complete;
		settings->on_body             = &on_body;

		parser->data = this;
		http_parser_init(parser, HTTP_RESPONSE);		
	}

	int http_response_parser::on_header_field(http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		switch (p.m_state)
		{
			case header_value:
				p.m_state = header_field;
				p.m_buffer = data;
				p.m_buffer_size = len;

				http_parser_pause(parser, 1);
				return 0;
				
			case header_field:
				p.m_hdrfield->append(data, len);
				break;

			default: EXT_UNREACHABLE();
		}

		return 0;
	}

	int http_response_parser::on_header_value(http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		switch (p.m_state)
		{
			case header_field:
				p.m_state = header_value;
			case header_value:
				p.m_hdrvalue->append(data, len);
				break;

			default: EXT_UNREACHABLE();
		}

		return 0;
	}

	int http_response_parser::on_headers_complete(http_parser * parser)
	{
		auto & p = get_this(parser);
		p.m_state = body;
		http_parser_pause(parser, 1);
		return 0;
	}

	bool http_response_parser::parse_header(std::istream & is, std::string & name, std::string & value)
	{
		if (headers_parsed()) return false;

		name.assign(m_buffer, m_buffer_size);
		value.clear();

		m_hdrfield = &name;
		m_hdrvalue = &value;

		for (;;)
		{
			is.peek();
			if (not is) throw_stream_error();

			auto & sb = static_cast<ext::streambuf &>(*is.rdbuf());
			auto * ptr = sb.gptr();
			std::size_t data_len = sb.egptr() - ptr;

			auto parsed = execute(ptr, data_len);
			sb.gbump(static_cast<int>(parsed));

			auto err = HTTP_PARSER_ERRNO(&m_parser);
			if (err == HPE_PAUSED)
			{
				on_parsed_header(name, value);
				http_parser_pause(&m_parser, 0);
				return true;
			}
			
			if (parsed != data_len)
				throw_parser_error(&m_parser);
		}
	}

	void http_response_parser::on_parsed_header(const std::string & name, const std::string & value)
	{
		m_deflated |= name == "Content-Encoding" &&
			(value == "gzip" || value == "deflate");
	}

	int http_response_parser::on_body(http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);

		p.m_buffer = data;
		p.m_buffer_size = len;

		http_parser_pause(parser, 1);
		return 0;
	}

	int http_response_parser::on_message_complete(http_parser * parser)
	{
		auto & p = get_this(parser);
		p.m_state = finished;
		return 0;
	}

	bool http_response_parser::parse_body(std::istream & is, const char *& buffer, std::size_t & buff_size)
	{
		if (not headers_parsed())
		{
			std::string name, value;
			while (parse_header(is, name, value))
				continue;
		}
		
		m_buffer_size = 0;
		while (not message_parsed())
		{
			is.peek();
			if (not is) throw_stream_error();

			auto & sb = static_cast<ext::streambuf &>(*is.rdbuf());
			auto * ptr = sb.gptr();
			std::size_t data_len = sb.egptr() - ptr;

			auto parsed = execute(ptr, data_len);
			sb.gbump(static_cast<int>(parsed));

			auto err = HTTP_PARSER_ERRNO(&m_parser);
			if (err == HPE_PAUSED)
			{
				buffer = m_buffer;
				buff_size = m_buffer_size;

				http_parser_pause(&m_parser, 0);
				return m_buffer_size != 0;
			}

			if (parsed != data_len)
				throw_parser_error(&m_parser);
		}

		return false;
	}

	void http_response_parser::reset()
	{
		m_state = start_state;

		m_buffer = nullptr;
		m_buffer_size = 0;
		m_deflated = false;

		init_parser(&m_parser, &m_settings);
	}

	http_response_parser::http_response_parser(const http_response_parser & other)
	{
		m_state = other.m_state;
		m_deflated = other.m_deflated;
		
		m_buffer = other.m_buffer;
		m_buffer_size = other.m_buffer_size;
		
		m_parser = other.m_parser;
		m_settings = other.m_settings;

		m_parser.data = this;
	}

	http_response_parser & http_response_parser::operator =(const http_response_parser & other)
	{
		if (this != &other)
		{
			this->~http_response_parser();
			new (this) http_response_parser(other);
		}

		return *this;
	}

	int parse_http_response(std::istream & is, std::string & response_body)
	{
		http_response_parser parser;

		std::string name, value;
		while (parser.parse_header(is, name, value))
			continue;

		const char * buffer;
		std::size_t len;

#ifdef EXT_ENABLE_CPPZLIB
		if (parser.deflated())
		{
			std::size_t sz = std::max<std::size_t>(1024, response_body.capacity());
			sz = std::min<std::size_t>(10 * 1024, sz);
			sz = std::max<std::size_t>(sz, response_body.size());
			response_body.resize(sz);

			zlib::inflate_stream inflator {MAX_WBITS + 32};
			inflator.set_out(ext::data(response_body), response_body.size());

			while (parser.parse_body(is, buffer, len))
			{
				inflator.set_in(buffer, len);
				do {
					if (not inflator.avail_out())
					{
						response_body.resize(sz = sz * 3 / 2);
						inflator.set_out(ext::data(response_body) + sz, response_body.size() - sz);
					}

					int res = ::inflate(inflator, Z_NO_FLUSH);
					switch (res)
					{
						case Z_OK: break;

						case Z_STREAM_END:
							assert(not inflator.avail_in());
							if (parser.parse_body(is, buffer, len))
								throw std::runtime_error("inconsistent deflated stream, trailing data after Z_STREAM_END");

							goto finished;

						case Z_NEED_DICT:
						case Z_BUF_ERROR:
						case Z_ERRNO:
						case Z_STREAM_ERROR:
						case Z_DATA_ERROR:
						case Z_MEM_ERROR:
						case Z_VERSION_ERROR:
						default:
							zlib::throw_zlib_error(res, inflator);
					}
				} while (inflator.avail_in());
			}

		finished:
			response_body.resize(inflator.total_out());
		}
		else
#endif
		{
			while (parser.parse_body(is, buffer, len))
				response_body.append(buffer, len);
		}
		
		return parser.http_code();
	}
}}
