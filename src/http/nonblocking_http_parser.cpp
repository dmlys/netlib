#include <cstddef>
#include <climits> // for CHAR_BIT
#include <cassert>
#include <cstring> // for std::memcpy
#include <string>
#include <string_view>
#include <algorithm>

#include <ext/config.hpp>
#include <ext/net/http/nonblocking_http_parser.hpp>

#include "http_parser.h"


namespace ext::net::http::http_server_utils
{
	const unsigned nonblocking_http_parser::request  = HTTP_REQUEST;
	const unsigned nonblocking_http_parser::response = HTTP_RESPONSE;

	const decltype(nonblocking_http_parser::settings_object_headers) nonblocking_http_parser::settings_object_headers = []
	{
		using result_type = decltype(nonblocking_http_parser::settings_object_headers);

		::http_parser_settings settings;
		http_parser_settings_init(&settings);

		settings.on_status           = &on_status;
		settings.on_header_field     = &on_status_complete;

		settings.on_url              = &on_url;
		settings.on_header_field     = &on_url_complete;

		//settings->on_header_field     = &on_header_field;
		//settings->on_header_value     = &on_header_value;

		settings.on_headers_complete = &on_headers_complete;
		//settings.on_body             = &on_body;
		settings.on_message_complete = &on_message_complete;

		static_assert(sizeof(settings_object_headers) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return reinterpret_cast<result_type &>(settings);
	}();

	const decltype(nonblocking_http_parser::settings_object_string_body) nonblocking_http_parser::settings_object_string_body = []
	{
		using result_type = decltype(nonblocking_http_parser::settings_object_string_body);

		::http_parser_settings settings;
		http_parser_settings_init(&settings);

		settings.on_status           = &on_status;
		settings.on_url              = &on_url;

		settings.on_header_field     = &on_header_field;
		settings.on_header_value     = &on_header_value;

		settings.on_headers_complete = &on_headers_complete;
		settings.on_body             = &on_string_body;
		settings.on_message_complete = &on_message_complete;

		static_assert(sizeof(settings_object_string_body) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return reinterpret_cast<result_type &>(settings);
	}();
	
	const decltype(nonblocking_http_parser::settings_object_vector_body) nonblocking_http_parser::settings_object_vector_body = []
	{
		using result_type = decltype(nonblocking_http_parser::settings_object_vector_body);

		::http_parser_settings settings;
		http_parser_settings_init(&settings);

		settings.on_status           = &on_status;
		settings.on_url              = &on_url;

		settings.on_header_field     = &on_header_field;
		settings.on_header_value     = &on_header_value;

		settings.on_headers_complete = &on_headers_complete;
		settings.on_body             = &on_vector_body;
		settings.on_message_complete = &on_message_complete;

		static_assert(sizeof(settings_object_vector_body) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return reinterpret_cast<result_type &>(settings);
	}();

	const decltype(nonblocking_http_parser::settings_object_no_body) nonblocking_http_parser::settings_object_no_body = []
	{
		using result_type = decltype(nonblocking_http_parser::settings_object_no_body);

		::http_parser_settings settings;
		http_parser_settings_init(&settings);

		settings.on_status           = &on_status;
		settings.on_url              = &on_url;

		settings.on_header_field     = &on_header_field;
		settings.on_header_value     = &on_header_value;

		settings.on_headers_complete = &on_headers_complete;
		settings.on_body             = &on_no_body;
		settings.on_message_complete = &on_message_complete;

		static_assert(sizeof(settings_object_no_body) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return reinterpret_cast<result_type &>(settings);
	}();
	

	inline nonblocking_http_parser & nonblocking_http_parser::get_this(::http_parser * parser) noexcept
	{
		return *static_cast<nonblocking_http_parser *>(parser->data);
	}

	inline ::http_parser & nonblocking_http_parser::get_parser() noexcept
	{
		static_assert(sizeof(m_parser_object) == sizeof(::http_parser),
			"::http_parser size is different than impl buffer");

		return *reinterpret_cast<::http_parser *>(&m_parser_object);
	}

	inline const ::http_parser & nonblocking_http_parser::get_parser() const noexcept
	{
		static_assert(sizeof(m_parser_object) == sizeof(::http_parser),
			"::http_parser size is different than impl buffer");

		return *reinterpret_cast<const ::http_parser *>(&m_parser_object);
	}

	inline const ::http_parser_settings & nonblocking_http_parser::get_settings() const noexcept
	{
		static_assert(sizeof(*m_settings_object) == sizeof(::http_parser_settings),
			"::http_parser_settings size is different than impl buffer");

		return *reinterpret_cast<const ::http_parser_settings *>(m_settings_object);
	}

	//header_map & http_server_request_parser::get_headers() const noexcept
	//{
	//	if (m_type == request)
	//		return m_request->headers;
	//	else
	//		return m_response->headers;
	//}
	//
	//std::string & http_server_request_parser::get_body() const noexcept
	//{
	//	if (m_type == request)
	//		return m_request->body;
	//	else
	//		return m_response->body;
	//}

	BOOST_NORETURN void nonblocking_http_parser::throw_parser_error(const ::http_parser * parser)
	{
		auto * errmsg = http_errno_description(HTTP_PARSER_ERRNO(parser));

		std::string msg = "ext::net::http_parser error: ";
		msg += errmsg;

		throw std::runtime_error(std::move(msg));
	}

	void nonblocking_http_parser::init_parser_internals() noexcept
	{
		auto * parser = &get_parser();
		parser->data = this;
		m_settings_object = &settings_object_headers;
		http_parser_init(parser, ::http_parser_type::HTTP_REQUEST);
	}

	void nonblocking_http_parser::init_body_parsing() noexcept
	{
		http_body * body = m_type == HTTP_REQUEST ? &m_request->body : &m_response->body;
		switch (static_cast<http_body_type>(body->index()))
		{
			case http_body_type::string:
				m_settings_object = &settings_object_string_body;
				m_strbody = std::get_if<std::string>(body);
				break;
			case http_body_type::vector:
				m_settings_object = &settings_object_vector_body;
				m_vecbody = std::get_if<std::vector<char>>(body);
				break;
			default:
				m_strbody = nullptr;
				m_settings_object = &settings_object_no_body;
		}
	}
	
	int nonblocking_http_parser::on_status(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		assert(p.m_state == status_state);

		auto & status = p.m_response->status;
		status.append(data, len);

		return 0;
	}

	int nonblocking_http_parser::on_status_complete(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);

		p.m_state = header_field;
		p.init_body_parsing();
		p.m_response->http_code = p.http_code();

		// save for later header parsing
		p.m_tmp.assign(data, len);

		::http_parser_pause(parser, 1);
		return 0;
	}

	int nonblocking_http_parser::on_url(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		assert(p.m_state == url_state);

		auto & url = p.m_request->url;
		url.append(data, len);

		return 0;
	}

	int nonblocking_http_parser::on_url_complete(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);

		p.m_state = header_field;
		p.init_body_parsing();
		p.m_request->http_version = p.http_version();

		// save for later header parsing
		p.m_tmp.assign(data, len);

		::http_parser_pause(parser, 1);
		return 0;
	}

	int nonblocking_http_parser::on_header_field(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		auto & tmp = p.m_tmp;

		switch (p.m_state)
		{
			case header_value:
				p.m_state = header_field;
				*p.m_header_value = tmp;
				tmp.assign(data, len);

				return 0;

			case header_field:
				tmp.append(data, len);
				break;

			default: EXT_UNREACHABLE();
		}

		return 0;
	}

	int nonblocking_http_parser::on_header_value(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		auto & tmp = p.m_tmp;
		auto & headers = *p.m_headers;

		switch (p.m_state)
		{
			case header_field:
				p.m_state = header_value;
				headers.emplace_back();
				headers.back().name = tmp;
				p.m_header_value = &headers.back().value;
				tmp.clear();

			case header_value:
				tmp.append(data, len);
				break;

			default: EXT_UNREACHABLE();
		}

		return 0;
	}

	int nonblocking_http_parser::on_headers_complete(::http_parser * parser)
	{
		auto & p = get_this(parser);

		if (p.m_state == header_value)
			*p.m_header_value = p.m_tmp;

		p.m_state = body_state;
		p.m_tmp.clear();

		if (p.m_state >= p.m_stop_state)
			::http_parser_pause(parser, 1);

		return 0;
	}

	int nonblocking_http_parser::on_string_body(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		p.m_strbody->append(data, len);

		return 0;
	}
	
	int nonblocking_http_parser::on_vector_body(::http_parser * parser, const char * data, size_t len)
	{
		auto & p = get_this(parser);
		p.m_vecbody->insert(p.m_vecbody->end(), data, data + len);
		
		return 0;
	}
	
	int nonblocking_http_parser::on_no_body(::http_parser * parser, const char * data, size_t len)
	{
		//auto & p = get_this(parser);
		//throw std::logic_error("invalid http body parsing, please configure parsing properly");
		return 1;
	}

	int nonblocking_http_parser::on_message_begin(::http_parser * parser)
	{
		return 0;
	}

	int nonblocking_http_parser::on_message_complete(::http_parser * parser)
	{
		auto & p = get_this(parser);
		p.m_state = finished;

		// step out from parsing, we should not parse next message
		http_parser_pause(parser, 1);
		return 0;
	}

	std::size_t nonblocking_http_parser::parse_some(state_type until, const char * data, std::size_t len)
	{
		if (m_state >= until) return 0;

		m_stop_state = until;
		std::size_t parsed = 0;
		std::size_t consumed;

		do
		{
			auto * parser   = &get_parser();
			auto * settings = &get_settings();

			consumed = http_parser_execute(parser, settings, data, len);
			auto err = HTTP_PARSER_ERRNO(parser);
			if (err != HPE_OK and err != HPE_PAUSED)
				throw_parser_error(parser);

			http_parser_pause(parser, 0);

			parsed += consumed;
			data += consumed;
			len -= consumed;

		} while (m_state < m_stop_state and len);

		return parsed;
	}

	bool nonblocking_http_parser::should_keep_alive() const noexcept
	{
		return ::http_should_keep_alive(&get_parser()) == 1;
	}

	bool nonblocking_http_parser::should_close() const noexcept
	{
		return ::http_should_keep_alive(&get_parser()) == 0;
	}

	int nonblocking_http_parser::http_version_major() const noexcept
	{
		return get_parser().http_major;
	}

	int nonblocking_http_parser::http_version_minor() const noexcept
	{
		return get_parser().http_minor;
	}

	int nonblocking_http_parser::http_version() const noexcept
	{
		return http_version_major() * 10 + http_version_minor();
	}

	int nonblocking_http_parser::http_code() const noexcept
	{
		return get_parser().status_code;
	}

	std::string nonblocking_http_parser::http_method() const
	{
		return ::http_method_str(static_cast<::http_method>(get_parser().method));
	}

	void nonblocking_http_parser::reset(http_request * request)
	{
		m_type = HTTP_REQUEST;
		m_state = start_state;
		m_stop_state = finished;
		m_flags = 0;
		m_tmp.clear();
		
		m_request = request;
		m_strbody = nullptr;
		m_headers = &request->headers;

		clear(*request);

		init_parser_internals();
	}

	void nonblocking_http_parser::reset(http_response * response)
	{
		m_type = HTTP_RESPONSE;
		m_state = start_state;
		m_stop_state = finished;
		m_flags = 0;
		m_tmp.clear();

		m_response = response;
		m_strbody = nullptr;
		m_headers = &response->headers;

		clear(*response);

		init_parser_internals();
	}

	void nonblocking_http_parser::set_body_destination(std::string & str)
	{
		m_strbody = &str;
		m_settings_object = &settings_object_string_body;
	}
	
	void nonblocking_http_parser::set_body_destination(std::vector<char> & vec)
	{
		m_vecbody = &vec;
		m_settings_object = &settings_object_vector_body;
	}
	
	nonblocking_http_parser::nonblocking_http_parser(nonblocking_http_parser && other)
	{
		m_type = other.m_type;
		m_state = other.m_state;
		m_stop_state = other.m_stop_state;
		m_flags = other.m_flags;

		m_strbody = other.m_strbody;
		m_headers = other.m_headers;
		m_header_value = other.m_header_value;
		m_response = other.m_response;

		std::memcpy(&m_parser_object, &other.m_parser_object, sizeof(m_parser_object));
		m_settings_object = other.m_settings_object;
		get_parser().data = this;
	}

	nonblocking_http_parser & nonblocking_http_parser::operator =(nonblocking_http_parser && other)
	{
		if (this != &other)
		{
			this->~nonblocking_http_parser();
			new (this) nonblocking_http_parser(std::move(other));
		}

		return *this;
	}
}
