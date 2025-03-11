#include <cstddef>
#include <climits> // for CHAR_BIT
#include <cassert>
#include <cstring> // for std::memcpy
#include <string>
#include <string_view>
#include <algorithm>

#include <ext/config.hpp>
#include <ext/range.hpp>
#include <ext/iostreams/streambuf.hpp>
#include <ext/net/socket_streambuf.hpp>
#include <ext/net/http/blocking_http_parser.hpp>

#include "http_parser.h"

namespace ext::net::http
{
	const decltype(blocking_http_parser::settings_object1) blocking_http_parser::settings_object1 = []
	{
		using result_type = decltype(blocking_http_parser::settings_object1);

		::http_parser_settings settings;
		http_parser_settings_init(&settings);

		settings.on_status           = &on_status;
		settings.on_header_field     = &on_status_complete;

		settings.on_url              = &on_url;
		settings.on_header_field     = &on_url_complete;

		//settings->on_header_field     = &on_header_field;
		//settings->on_header_value     = &on_header_value;

		settings.on_headers_complete = &on_headers_complete;
		settings.on_body             = &on_body;
		settings.on_message_complete = &on_message_complete;

		static_assert(sizeof(settings_object1) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return reinterpret_cast<result_type &>(settings);
	}();

	const decltype(blocking_http_parser::settings_object2) blocking_http_parser::settings_object2 = []
	{
		using result_type = decltype(blocking_http_parser::settings_object2);

		::http_parser_settings settings;
		http_parser_settings_init(&settings);

		settings.on_status           = &on_status;
		settings.on_url              = &on_url;

		settings.on_header_field     = &on_header_field;
		settings.on_header_value     = &on_header_value;

		settings.on_headers_complete = &on_headers_complete;
		settings.on_body             = &on_body;
		settings.on_message_complete = &on_message_complete;

		static_assert(sizeof(settings_object2) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return reinterpret_cast<result_type &>(settings);
	}();


	const unsigned blocking_http_parser::request  = HTTP_REQUEST;
	const unsigned blocking_http_parser::response = HTTP_RESPONSE;

	inline static void check_stream(std::streambuf & sb)
	{
		if (auto * ssb = dynamic_cast<socket_streambuf *>(&sb))
		{
			if (ssb->last_error())
				ssb->throw_last_error();
		}
	}
	
	inline static bool peek(std::streambuf & sb)
	{
		typedef std::streambuf::traits_type traits_type;
		bool eof = traits_type::eq_int_type(traits_type::eof(), sb.sgetc());
		
		if (eof)
			check_stream(sb);
		
		return not eof;
	}

	inline blocking_http_parser & blocking_http_parser::get_this(::http_parser * parser) noexcept
	{
		return *static_cast<blocking_http_parser *>(parser->data);
	}

	inline ::http_parser * blocking_http_parser::get_parser() noexcept
	{
		static_assert(sizeof(m_parser_object) == sizeof(::http_parser),
			"::http_parser size is different than impl buffer");

		return reinterpret_cast<::http_parser *>(&m_parser_object);
	}

	inline const ::http_parser * blocking_http_parser::get_parser() const noexcept
	{
		static_assert(sizeof(m_parser_object) == sizeof(::http_parser),
			"::http_parser size is different than impl buffer");

		return reinterpret_cast<const ::http_parser *>(&m_parser_object);
	}

	inline const ::http_parser_settings * blocking_http_parser::get_settings() const noexcept
	{
		static_assert(sizeof(*m_settings_object) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return reinterpret_cast<const ::http_parser_settings *>(m_settings_object);
	}

	BOOST_NORETURN void blocking_http_parser::throw_parser_error(const ::http_parser * parser)
	{
		auto * errmsg = http_errno_description(HTTP_PARSER_ERRNO(parser));

		std::string msg = "ext::net::http_parser error: ";
		msg += errmsg;

		throw std::runtime_error(std::move(msg));
	}

	//BOOST_NORETURN void blocking_http_parser::throw_stream_read_failure()
	//{
	//	throw std::runtime_error("ext::net::http_parser: stream read failure");
	//}

	void blocking_http_parser::init_parser_internals()
	{
		auto * parser = get_parser();
		parser->data = this;
		m_settings_object = &settings_object1;
		http_parser_init(parser,  static_cast<::http_parser_type>(m_type));
	}

	int blocking_http_parser::on_status(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		assert(p.m_state == status_state);
		
		if (p.m_status_val) p.m_status_val->append(data, len);
		return 0;
	}

	int blocking_http_parser::on_status_complete(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);

		p.m_state = header_field;
		p.m_settings_object = &settings_object2;

		// save for later header parsing
		p.m_buffer = data;
		p.m_buffer_size = len;

		// step out from parsing
		http_parser_pause(parser, 1);
		return 0;
	}

	int blocking_http_parser::on_url(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		assert(p.m_state == url_state);

		if (p.m_url_val) p.m_url_val->append(data, len);
		return 0;
	}

	int blocking_http_parser::on_url_complete(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);

		p.m_state = header_field;
		p.m_settings_object = &settings_object2;

		// save for later header parsing
		p.m_buffer = data;
		p.m_buffer_size = len;

		// step out from parsing
		http_parser_pause(parser, 1);
		return 0;
	}

	int blocking_http_parser::on_header_field(::http_parser * parser, const char * data, size_t len)
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

	int blocking_http_parser::on_header_value(::http_parser * parser, const char * data, size_t len)
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

	int blocking_http_parser::on_headers_complete(::http_parser * parser)
	{
		auto & p = get_this(parser);
		p.m_state = body_state;

		http_parser_pause(parser, 1);
		return 0;
	}

	int blocking_http_parser::on_body(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);

		p.m_buffer = data;
		p.m_buffer_size = len;

		http_parser_pause(parser, 1);
		return 0;
	}

	int blocking_http_parser::on_message_begin(::http_parser * parser)
	{
		return 0;
	}

	int blocking_http_parser::on_message_complete(::http_parser * parser)
	{
		auto & p = get_this(parser);
		p.m_state = finished;

		// step out from parsing, we should not parse next message
		http_parser_pause(parser, 1);
		return 0;
	}

	bool blocking_http_parser::parse_status(std::streambuf & sb, std::string & str)
	{
		auto * parser = get_parser();

		if (status_parsed()) return false;

		str.clear();
		m_status_val = &str;

		for (;;)
		{
			peek(sb);

			auto & esb = static_cast<ext::streambuf &>(sb);
			auto * ptr = esb.gptr();
			std::size_t data_len = esb.egptr() - ptr;

			auto parsed = http_parser_execute(parser, get_settings(), ptr, data_len);
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

	bool blocking_http_parser::parse_url(std::streambuf & sb, std::string & str)
	{
		// actually code identical to parse_status and we can just call it
		// (m_status_val shares same space via union with m_url_val)
		return parse_status(sb, str);
	}

	bool blocking_http_parser::parse_header(std::streambuf & sb, std::string & name, std::string & value)
	{
		auto * parser = get_parser();

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
			peek(sb);

			auto & esb = static_cast<ext::streambuf &>(sb);
			auto * ptr = esb.gptr();
			std::size_t data_len = esb.egptr() - ptr;

			auto parsed = http_parser_execute(parser, get_settings(), ptr, data_len);
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

	void blocking_http_parser::on_parsed_header(const std::string & name, const std::string & value)
	{

	}

	bool blocking_http_parser::parse_body(std::streambuf & sb, const char *& buffer, std::size_t & buff_size)
	{
		auto * parser = get_parser();

		if (not headers_parsed())
		{
			std::string name, value;
			while (parse_header(sb, name, value))
				continue;
		}
		
		m_buffer_size = 0;
		while (not message_parsed())
		{
			peek(sb);

			auto & esb = static_cast<ext::streambuf &>(sb);
			auto * ptr = esb.gptr();
			std::size_t data_len = esb.egptr() - ptr;

			auto parsed = http_parser_execute(parser, get_settings(), ptr, data_len);
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

	bool blocking_http_parser::should_keep_alive() const noexcept
	{
		return ::http_should_keep_alive(get_parser()) == 1;
	}

	bool blocking_http_parser::should_close() const noexcept
	{
		return ::http_should_keep_alive(get_parser()) == 0;
	}

	int blocking_http_parser::http_version_major() const noexcept
	{
		return get_parser()->http_major;
	}

	int blocking_http_parser::http_version_minor() const noexcept
	{
		return get_parser()->http_minor;
	}

	int blocking_http_parser::http_version() const noexcept
	{
		return http_version_major() * 10 + http_version_minor();
	}

	int blocking_http_parser::http_code() const noexcept
	{
		return get_parser()->status_code;
	}

	std::string blocking_http_parser::http_method() const
	{
		return ::http_method_str(static_cast<::http_method>(get_parser()->method));
	}

	void blocking_http_parser::reset(unsigned type)
	{
		m_type = type;
		m_state = start_state;
		m_flags = 0;

		m_buffer = nullptr;
		m_buffer_size = 0;

		init_parser_internals();
	}

	blocking_http_parser::blocking_http_parser(blocking_http_parser && other)
	{
		m_type = other.m_type;
		m_state = other.m_state;
		m_flags = other.m_flags;
		
		m_buffer = other.m_buffer;
		m_buffer_size = other.m_buffer_size;
		
		std::memcpy(&m_parser_object, &other.m_parser_object, sizeof(m_parser_object));
		m_settings_object = other.m_settings_object;
		get_parser()->data = this;

		//m_parser = other.m_parser;
		//m_settings = other.m_settings;

		//m_parser.data = this;

		other.reset();
	}

	blocking_http_parser & blocking_http_parser::operator =(blocking_http_parser && other)
	{
		if (this != &other)
		{
			this->~blocking_http_parser();
			new (this) blocking_http_parser(std::move(other));
		}

		return *this;
	}

	bool blocking_http_parser::parse_status(std::istream & is, std::string & str)
	{
		return parse_status(*is.rdbuf(), str);
	}

	bool blocking_http_parser::parse_url(std::istream & is, std::string & str)
	{
		// actually code identical to parse_status and we can just call it
		// (m_status_val shares same space via union with m_url_val)
		return parse_status(is, str);
	}

	bool blocking_http_parser::parse_header(std::istream & is, std::string & name, std::string & value)
	{
		return parse_header(*is.rdbuf(), name, value);
	}

	bool blocking_http_parser::parse_body(std::istream & is, const char *& buffer, std::size_t & buff_size)
	{
		return parse_body(*is.rdbuf(), buffer, buff_size);
	}

	void blocking_http_parser::parse_body(std::streambuf & sb, std::string & body)
	{
		const char * buffer;
		std::size_t bufsize;
		while (parse_body(sb, buffer, bufsize))
			ext::append(body, buffer, buffer + bufsize);
	}

	void blocking_http_parser::parse_body(std::streambuf & sb, std::vector<char> & body)
	{
		const char * buffer;
		std::size_t bufsize;
		while (parse_body(sb, buffer, bufsize))
			ext::append(body, buffer, buffer + bufsize);
	}

	void blocking_http_parser::parse_body(std::istream & is, std::string & body)
	{
		return parse_body(*is.rdbuf(), body);
	}

	void blocking_http_parser::parse_body(std::istream & is, std::vector<char> & body)
	{
		return parse_body(*is.rdbuf(), body);
	}

	void blocking_http_parser::parse_trailing(std::streambuf & sb)
	{
		const char * buf;
		std::size_t sz;

		while (parse_body(sb, buf, sz));
	}

	void blocking_http_parser::parse_trailing(std::istream & is)
	{
		parse_trailing(*is.rdbuf());
	}
}
