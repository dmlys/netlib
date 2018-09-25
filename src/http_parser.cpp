#include <cassert>
#include <algorithm>

#include <ext/config.hpp>
#include <ext/cppzlib.hpp>
#include <ext/range.hpp>
#include <ext/iostreams/streambuf.hpp>
#include <ext/netlib/http_parser.hpp>

#include "http_parser.h"

namespace ext {
namespace netlib
{
	const unsigned http_parser::request  = HTTP_REQUEST;
	const unsigned http_parser::response = HTTP_RESPONSE;

	inline static bool peek(std::streambuf & sb)
	{
		typedef std::streambuf::traits_type traits_type;
		return not traits_type::eq_int_type(traits_type::eof(), sb.sgetc());
	}

	inline http_parser & http_parser::get_this(::http_parser * parser) noexcept
	{
		return *static_cast<http_parser *>(parser->data);
	}

	inline ::http_parser & http_parser::get_parser() noexcept 
	{
		static_assert(sizeof(m_parser_object) == sizeof(::http_parser),
			"::http_parser size is different than impl buffer");

		return *reinterpret_cast<::http_parser *>(&m_parser_object);
	}

	inline const ::http_parser & http_parser::get_parser() const noexcept 
	{
		static_assert(sizeof(m_parser_object) == sizeof(::http_parser),
			"::http_parser size is different than impl buffer");

		return *reinterpret_cast<const ::http_parser *>(&m_parser_object);
	}

	inline ::http_parser_settings & http_parser::get_settings() noexcept 
	{ 
		static_assert(sizeof(m_settings_object) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return *reinterpret_cast<::http_parser_settings *>(&m_settings_object);
	}

	inline const ::http_parser_settings & http_parser::get_settings() const noexcept
	{
		static_assert(sizeof(m_settings_object) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return *reinterpret_cast<const ::http_parser_settings *>(&m_settings_object);
	}

	BOOST_NORETURN void http_parser::throw_parser_error(const ::http_parser * parser)
	{
		auto * errmsg = http_errno_description(HTTP_PARSER_ERRNO(parser));

		std::string msg = "ext::netlib::http_parser error: ";
		msg += errmsg;

		throw std::runtime_error(std::move(msg));
	}

	BOOST_NORETURN void http_parser::throw_stream_read_failure()
	{
		throw std::runtime_error("ext::netlib::http_parser: stream read failure");
	}

	void http_parser::init_parser(::http_parser * parser, ::http_parser_settings * settings)
	{
		http_parser_settings_init(settings);
		
		settings->on_status           = &on_status;
		settings->on_header_field     = &on_status_complete;
		
		settings->on_url              = &on_url;
		settings->on_header_field     = &on_url_complete;
		
		//settings->on_header_field     = &on_header_field;
		//settings->on_header_value     = &on_header_value;
		
		settings->on_headers_complete = &on_headers_complete;
		settings->on_body             = &on_body;
		settings->on_message_complete = &on_message_complete;
		
		parser->data = this;
		http_parser_init(parser, static_cast<::http_parser_type>(m_type));
	}

	int http_parser::on_status(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		assert(p.m_state == status_state);
		
		if (p.m_status_val) p.m_status_val->append(data, len);
		return 0;
	}

	int http_parser::on_status_complete(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		auto & settings = p.get_settings();

		p.m_state = header_field;
		settings.on_header_field = &on_header_field;
		settings.on_header_value = &on_header_value;

		// save for later header parsing
		p.m_buffer = data;
		p.m_buffer_size = len;

		// step out from parsing
		http_parser_pause(parser, 1);
		return 0;
	}

	int http_parser::on_url(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		assert(p.m_state == url_state);

		if (p.m_url_val) p.m_url_val->append(data, len);
		return 0;
	}

	int http_parser::on_url_complete(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		auto & settings = p.get_settings();

		p.m_state = header_field;
		settings.on_header_field = &on_header_field;
		settings.on_header_value = &on_header_value;

		// save for later header parsing
		p.m_buffer = data;
		p.m_buffer_size = len;

		// step out from parsing
		http_parser_pause(parser, 1);
		return 0;
	}

	int http_parser::on_header_field(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		switch (p.m_state)
		{
			case header_value:
				p.m_state = header_field;
				p.m_buffer = data;
				p.m_buffer_size = len;

				// step out from parsing, we have complete name:value header pair
				http_parser_pause(parser, 1);
				return 0;
				
			case header_field:
				p.m_hdrfield->append(data, len);
				break;

			default: EXT_UNREACHABLE();
		}

		return 0;
	}

	int http_parser::on_header_value(::http_parser * parser, const char * data, size_t len)
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

	int http_parser::on_headers_complete(::http_parser * parser)
	{
		auto & p = get_this(parser);
		p.m_state = body_state;

		http_parser_pause(parser, 1);
		return 0;
	}

	int http_parser::on_body(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);

		p.m_buffer = data;
		p.m_buffer_size = len;

		http_parser_pause(parser, 1);
		return 0;
	}

	int http_parser::on_message_begin(::http_parser * parser)
	{
		return 0;
	}

	int http_parser::on_message_complete(::http_parser * parser)
	{
		auto & p = get_this(parser);
		p.m_state = finished;

		// step out from parsing, we should not parse next message
		http_parser_pause(parser, 1);
		return 0;
	}

	bool http_parser::parse_status(std::streambuf & sb, std::string & str)
	{
		auto * parser   = &get_parser();
		auto * settings = &get_settings();

		if (status_parsed()) return false;

		str.clear();
		m_status_val = &str;

		for (;;)
		{
			if (not peek(sb)) throw_stream_read_failure();

			auto & esb = static_cast<ext::streambuf &>(sb);
			auto * ptr = esb.gptr();
			std::size_t data_len = esb.egptr() - ptr;

			auto parsed = http_parser_execute(parser, settings, ptr, data_len);
			esb.gbump(static_cast<int>(parsed));

			auto err = HTTP_PARSER_ERRNO(parser);
			if (err == HPE_PAUSED)
			{
				http_parser_pause(parser, 0);
				return true;
			}

			if (parsed != data_len)
				throw_parser_error(parser);
		}
	}

	bool http_parser::parse_url(std::streambuf & sb, std::string & str)
	{
		// actually code identical to parse_status and we can just call it
		// (m_status_val shares same space via union with m_url_val)
		return parse_status(sb, str);
	}

	bool http_parser::parse_header(std::streambuf & sb, std::string & name, std::string & value)
	{
		auto * parser   = &get_parser();
		auto * settings = &get_settings();

		if (headers_parsed()) return false;

		if (not status_parsed())
		{
			while (parse_status(sb, value))
				continue;
		}

		name.assign(m_buffer, m_buffer_size);
		value.clear();

		m_hdrfield = &name;
		m_hdrvalue = &value;

		for (;;)
		{
			if (not peek(sb)) throw_stream_read_failure();

			auto & esb = static_cast<ext::streambuf &>(sb);
			auto * ptr = esb.gptr();
			std::size_t data_len = esb.egptr() - ptr;

			auto parsed = http_parser_execute(parser, settings, ptr, data_len);
			esb.gbump(static_cast<int>(parsed));

			auto err = HTTP_PARSER_ERRNO(parser);
			if (err == HPE_PAUSED)
			{
				on_parsed_header(name, value);
				http_parser_pause(parser, 0);
				return true;
			}
			
			if (parsed != data_len)
				throw_parser_error(parser);
		}
	}

	void http_parser::on_parsed_header(const std::string & name, const std::string & value)
	{
		m_deflated |= name == "Content-Encoding" &&
			(value == "gzip" || value == "deflate");
	}

	bool http_parser::parse_body(std::streambuf & sb, const char *& buffer, std::size_t & buff_size)
	{
		auto * parser = &get_parser();
		auto * settings = &get_settings();

		if (not headers_parsed())
		{
			std::string name, value;
			while (parse_header(sb, name, value))
				continue;
		}
		
		m_buffer_size = 0;
		while (not message_parsed())
		{
			if (not peek(sb)) throw_stream_read_failure();

			auto & esb = static_cast<ext::streambuf &>(sb);
			auto * ptr = esb.gptr();
			std::size_t data_len = esb.egptr() - ptr;

			auto parsed = http_parser_execute(parser, settings, ptr, data_len);
			esb.gbump(static_cast<int>(parsed));

			auto err = HTTP_PARSER_ERRNO(parser);
			if (err == HPE_PAUSED)
			{
				buffer = m_buffer;
				buff_size = m_buffer_size;

				http_parser_pause(parser, 0);
				return m_buffer_size != 0;
			}

			if (parsed != data_len)
				throw_parser_error(parser);
		}

		return false;
	}

	bool http_parser::should_keep_alive() const noexcept
	{
		return ::http_should_keep_alive(&get_parser()) == 1;
	}

	bool http_parser::should_close() const noexcept
	{
		return ::http_should_keep_alive(&get_parser()) == 0;
	}

	int http_parser::http_version_major() const noexcept
	{
		return get_parser().http_major;
	}

	int http_parser::http_version_minor() const noexcept
	{
		return get_parser().http_minor;
	}

	int http_parser::http_version() const noexcept
	{
		return http_version_major() * 10 + http_version_minor();
	}

	int http_parser::http_code() const noexcept
	{
		return get_parser().status_code;
	}

	std::string http_parser::http_method() const
	{
		return ::http_method_str(static_cast<::http_method>(get_parser().method));
	}

	void http_parser::reset(unsigned type)
	{
		m_state = start_state;

		m_buffer = nullptr;
		m_buffer_size = 0;
		m_deflated = false;
		m_type = type;

		auto * parser = &get_parser();
		auto * settings = &get_settings();
		init_parser(parser, settings);
	}

	http_parser::http_parser(http_parser && other)
	{
		m_state = other.m_state;
		m_type = other.m_type;
		m_deflated = other.m_deflated;
		
		m_buffer = other.m_buffer;
		m_buffer_size = other.m_buffer_size;
		
		std::memcpy(&m_parser_object, &other.m_parser_object, sizeof(m_parser_object));
		std::memcpy(&m_settings_object, &other.m_settings_object, sizeof(m_parser_object));
		get_parser().data = this;

		//m_parser = other.m_parser;
		//m_settings = other.m_settings;

		//m_parser.data = this;

		other.reset();
	}

	http_parser & http_parser::operator =(http_parser && other)
	{
		if (this != &other)
		{
			this->~http_parser();
			new (this) http_parser(std::move(other));
		}

		return *this;
	}

	bool http_parser::parse_status(std::istream & is, std::string & str)
	{
		return parse_status(*is.rdbuf(), str);
	}

	bool http_parser::parse_url(std::istream & is, std::string & str)
	{
		// actually code identical to parse_status and we can just call it
		// (m_status_val shares same space via union with m_url_val)
		return parse_status(is, str);
	}

	bool http_parser::parse_header(std::istream & is, std::string & name, std::string & value)
	{
		return parse_header(*is.rdbuf(), name, value);
	}

	bool http_parser::parse_body(std::istream & is, const char *& buffer, std::size_t & buff_size)
	{
		return parse_body(*is.rdbuf(), buffer, buff_size);
	}

	void parse_trailing(http_parser & parser, std::streambuf & sb)
	{
		const char * buf;
		std::size_t sz;

		while (parser.parse_body(sb, buf, sz));
	}

	void parse_trailing(http_parser & parser, std::istream & is)
	{
		parse_trailing(parser, *is.rdbuf());
	}


	void parse_http_body(http_parser & parser, std::streambuf & sb, std::string & body, std::string * pstatus_url /* = nullptr */)
	{
		std::string name, value;
		const char * buffer;
		std::size_t len;
		std::string & status_url = pstatus_url ? *pstatus_url : value;

		while (parser.parse_status(sb, status_url))
			continue;
		
		while (parser.parse_header(sb, name, value))
			continue;

		if (parser.deflated())
		{
#ifdef EXT_ENABLE_CPPZLIB
			std::size_t sz = std::max<std::size_t>(1024, body.capacity());
			sz = std::min<std::size_t>(10 * 1024, sz);
			sz = std::max<std::size_t>(sz, body.size());
			body.resize(sz);

			zlib::inflate_stream inflator {MAX_WBITS + 32};
			inflator.set_out(ext::data(body), body.size());

			while (parser.parse_body(sb, buffer, len))
			{
				inflator.set_in(buffer, len);
				do {
					if (not inflator.avail_out())
					{
						auto newsz = sz * 3 / 2;
						body.resize(newsz);
						inflator.set_out(ext::data(body) + sz, newsz - sz);
						sz = newsz;
					}

					int res = ::inflate(inflator, Z_NO_FLUSH);
					switch (res)
					{
						case Z_OK: break;

						case Z_STREAM_END:
							assert(not inflator.avail_in());
							if (parser.parse_body(sb, buffer, len))
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
			body.resize(inflator.total_out());
#else
			throw std::runtime_error("can't inflate compressed stream, ext::netlib::http_parser built without zlib support");
#endif
		}
		else
		{
			while (parser.parse_body(sb, buffer, len))
				body.append(buffer, len);
		}
	}

	void parse_http_body(http_parser & parser, std::istream & is, std::string & body, std::string * status_or_url)
	{
		return parse_http_body(parser, *is.rdbuf(), body, status_or_url);
	}



	int parse_http_response(http_parser & parser, std::streambuf & sb, std::string & response_body)
	{
		parse_http_body(parser, sb, response_body);
		return parser.http_code();
	}
	
	int parse_http_response(http_parser & parser, std::istream & is, std::string & response_body)
	{
		return parse_http_response(parser, *is.rdbuf(), response_body);
	}

	int parse_http_response(std::streambuf & sb, std::string & response_body)
	{
		http_parser parser(http_parser::response);
		return parse_http_response(parser, sb, response_body);
	}

	int parse_http_response(std::istream & is, std::string & response_body)
	{
		return parse_http_response(*is.rdbuf(), response_body);
	}


	void parse_http_request(http_parser & parser, std::streambuf & sb, std::string & method, std::string & url, std::string & request_body)
	{
		parse_http_body(parser, sb, request_body, &url);
		method = parser.http_method();
	}

	void parse_http_request(http_parser & parser, std::istream & is, std::string & method, std::string & url, std::string & request_body)
	{
		return parse_http_request(parser, *is.rdbuf(), method, url, request_body);
	}

	void parse_http_request(std::streambuf & sb, std::string & method, std::string & url, std::string & request_body)
	{
		http_parser parser(http_parser::request);
		parse_http_request(parser, sb, method, url, request_body);
	}

	void parse_http_request(std::istream & is, std::string & method, std::string & url, std::string & request_body)
	{
		return parse_http_request(*is.rdbuf(), method, url, request_body);
	}
}}
