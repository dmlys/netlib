#pragma once
#include <cstddef>
#include <climits> // for CHAR_BIT
#include <string>
#include <string_view>
#include <vector>
#include <tuple>

#include <streambuf>
#include <istream>

#include <type_traits> // for aligned_storage
#include <boost/config.hpp>
#include <ext/net/http/http_types.hpp>

// from http_parser.h
struct http_parser;
struct http_parser_settings;

namespace ext::net::http::http_server_utils
{
	/// simple non blocking http parser, based on ::http_parser
	class nonblocking_http_parser
	{
	public:
		enum state_type : unsigned
		{
			status_state, url_state = status_state,
			header_field, header_value,
			body_state, finished,

			start_state = status_state
		};

		static const unsigned request;
		static const unsigned response;

	private:
		//state_type m_state;
		unsigned m_type       : 2;
		unsigned m_state      : 3;
		unsigned m_stop_state : 3;
		unsigned m_flags      : sizeof(unsigned) * CHAR_BIT - 2 - 3 - 3;

		union { http_request * m_request; http_response * m_response; };
		union { std::string * m_strbody; std::vector<char> * m_vecbody; };
		std::string m_tmp;
		std::string * m_header_value;
		http_headers_vector * m_headers;

		// Including http_parser.h is somewhat unwanted - it's a C source with no namespace at all.
		// Instead we declare byte array of same size and reinterpret_cast it were necessary.
		// Sort of compiler firewall.

		//::http_parser m_parser;
		//::http_parser_settings m_settings;

		static constexpr auto HTTP_PARSER_SIZE =
			+ 32  // type + flags + .. + index
			+ 32  // nread
			+ 64  // content length
			+ 32  // http_ver
			+ 32  // status_code .. errno upgrade
			+ sizeof(void *) * CHAR_BIT; // data

		static constexpr auto HTTP_PARSER_SETTINGS_SIZE =
			8 * sizeof(void *) * CHAR_BIT; // settings structure have 8 callbacks

		std::aligned_storage_t<HTTP_PARSER_SIZE / CHAR_BIT, alignof(std::uint64_t)> m_parser_object;
		std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> const * m_settings_object;

		static const std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> settings_object_headers;
		static const std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> settings_object_string_body;
		static const std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> settings_object_vector_body;
		static const std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> settings_object_no_body;

	private: // others
		BOOST_NORETURN static void throw_parser_error(const ::http_parser * parser);

	private:
		static nonblocking_http_parser & get_this(::http_parser * parser) noexcept;

		      ::http_parser & get_parser()       noexcept;
		const ::http_parser & get_parser() const noexcept;
		const ::http_parser_settings & get_settings() const noexcept;

		//header_map & get_headers() const noexcept;
		//std::string & get_body() const noexcept;

		// ::http_parser callbacks
		static int on_status(::http_parser * parser, const char * data, size_t len);
		static int on_status_complete(::http_parser * parser, const char * data, size_t len);
		static int on_url(::http_parser * parser, const char * data, size_t len);
		static int on_url_complete(::http_parser * parser, const char * data, size_t len);
		static int on_header_field(::http_parser * parser, const char * data, size_t len);
		static int on_header_value(::http_parser * parser, const char * data, size_t len);
		static int on_headers_complete(::http_parser * parser);
		static int on_string_body(::http_parser * parser, const char * data, size_t len);
		static int on_vector_body(::http_parser * parser, const char * data, size_t len);
		static int on_no_body(::http_parser * parser, const char * data, size_t len);
		static int on_message_begin(::http_parser * parser);
		static int on_message_complete(::http_parser * parser);

		void init_parser_internals() noexcept;
		void init_body_parsing() noexcept;

	public: // main process methods
		/// resets state of a parser and prepares it for parsing a message
		void reset(http_request  * request);
		void reset(http_response * response);
		void reset(std::nullptr_t) { m_request = nullptr; }
		
		// should only be called after headers are parsed
		void set_body_destination(std::string & str);
		void set_body_destination(std::vector<char> & vec);

		bool status_parsed()  const noexcept { return m_state >  status_state; }
		bool url_parsed()     const noexcept { return m_state >  url_state; }
		bool headers_parsed() const noexcept { return m_state >= body_state; }
		bool message_parsed() const noexcept { return m_state == finished; }

		/// Does some parsing: returns consumed amount. Can return less than "len"
		/// Parses until some state is reached: headers parsed, message parsed, etc
		/// Throws std::runtime_error on parse errors.
		std::size_t parse_some(state_type until, const char * data, std::size_t len);

		/// Does some parsing: returns consumed amount. Can return less than "len"
		/// Throws std::runtime_error on parse errors.
		std::size_t parse_message(const char * data, std::size_t len) { return parse_some(finished, data, len); }
		/// Does some parsing: returns consumed amount. Can return less than "len"
		/// Throws std::runtime_error on parse errors.
		std::size_t parse_headers(const char * data, std::size_t len) { return parse_some(body_state, data, len); }

	public:
		bool should_keep_alive() const noexcept;
		bool should_close()      const noexcept;

		int http_version_major() const noexcept;
		int http_version_minor() const noexcept;
		// major * 10 + minor: 20, 11, 10, 09
		int http_version() const noexcept;

		int http_code() const noexcept;
		/// result will be in upper case: POST, GET, etc
		std::string http_method() const;

		/// can be useful for error and some other info extracting
		const ::http_parser & parser() const { return get_parser(); }

	public:
		nonblocking_http_parser() { m_request = nullptr; }
		nonblocking_http_parser(http_request  * request)  { reset(request); }
		nonblocking_http_parser(http_response * response) { reset(response); }

		nonblocking_http_parser(nonblocking_http_parser &&);
		nonblocking_http_parser & operator =(nonblocking_http_parser &&);

		nonblocking_http_parser(const nonblocking_http_parser &) = delete;
		nonblocking_http_parser & operator =(const nonblocking_http_parser &) = delete;
	};
}
