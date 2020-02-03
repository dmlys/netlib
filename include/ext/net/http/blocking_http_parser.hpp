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

// from http_parser.h
struct http_parser;
struct http_parser_settings;

namespace ext::net::http
{
	/// simple blocking http parser, based on ::http_parser
	class blocking_http_parser
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
		unsigned m_type     : 2;
		unsigned m_state    : 3;
		unsigned m_flags    : sizeof(unsigned) * CHAR_BIT - 2 - 3;

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

		static const std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> settings_object1;
		static const std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> settings_object2;

		union
		{
			struct
			{
				std::string * m_status_val;
			};

			struct
			{
				std::string * m_url_val;
			};

			struct
			{
				std::string * m_hdrfield;
				std::string * m_hdrvalue;
			};

			struct
			{
				const char * m_buffer;
				std::size_t m_buffer_size;
			};
		};
		
	private: // others
		BOOST_NORETURN static void throw_parser_error(const ::http_parser * parser);
		BOOST_NORETURN static void throw_stream_read_failure();

	private:
		static blocking_http_parser & get_this(::http_parser * parser) noexcept;

		      ::http_parser & get_parser()       noexcept;
		const ::http_parser & get_parser() const noexcept;
		const ::http_parser_settings & get_settings() const noexcept;

		// ::http_parser callbacks
		static int on_status(::http_parser * parser, const char * data, size_t len);
		static int on_status_complete(::http_parser * parser, const char * data, size_t len);
		static int on_url(::http_parser * parser, const char * data, size_t len);
		static int on_url_complete(::http_parser * parser, const char * data, size_t len);
		static int on_header_field(::http_parser * parser, const char * data, size_t len);
		static int on_header_value(::http_parser * parser, const char * data, size_t len);
		static int on_headers_complete(::http_parser * parser);
		static int on_body(::http_parser * parser, const char * data, size_t len);
		static int on_message_begin(::http_parser * parser);
		static int on_message_complete(::http_parser * parser);
		
		void init_parser_internals();
		void on_parsed_header(const std::string & name, const std::string & value);

	public: // main process methods
		/// resets state of a parser and prepares it for parsing a message
		void reset() { reset(m_type); }
		void reset(unsigned type);

		bool status_parsed()  const noexcept { return m_state >  status_state; }
		bool url_parsed()     const noexcept { return m_state >  url_state; }
		bool headers_parsed() const noexcept { return m_state >= body_state; }
		bool message_parsed() const noexcept { return m_state == finished; }

		bool get_flag(unsigned n) const noexcept { return m_flags & (1u << n); }
		void set_flag(unsigned n)       noexcept { m_flags |=   1u << n; }
		void reset_flag(unsigned n)     noexcept { m_flags &= ~(1u << n); }
		void flip_flag(unsigned n)      noexcept { m_flags ^=   1u << n; }
		void set_flag(unsigned n, bool value) noexcept { m_flags ^= (-static_cast<unsigned>(value) ^ m_flags) & (1u << n); }

		inline bool deflated() const noexcept { return get_flag(1); }
		inline void deflated(bool value) noexcept { return set_flag(1, value); }

		bool parse_status(std::streambuf & sb, std::string & str);
		bool parse_url(std::streambuf & sb, std::string & str);
		bool parse_header(std::streambuf & sb, std::string & name, std::string & value);
		bool parse_body(std::streambuf & sb, const char *& buffer, std::size_t & buff_size);

		bool parse_status(std::istream & is, std::string & str);
		bool parse_url(std::istream & is, std::string & str);
		bool parse_header(std::istream & is, std::string & name, std::string & value);
		bool parse_body(std::istream & is, const char *& buffer, std::size_t & buff_size);

		void parse_body(std::streambuf & sb, std::string & body);
		void parse_body(std::streambuf & sb, std::vector<char> & body);
		void parse_body(std::istream & is, std::string & body);
		void parse_body(std::istream & is, std::vector<char> & body);

	public:
		/// parses http data: headers, body; until whole http request/response is fully parsed,
		/// and streambuf/istream does not contain any trailing data
		void parse_trailing(std::streambuf & sb);
		void parse_trailing(std::istream & is);

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
		blocking_http_parser() : blocking_http_parser(request | response) {}
		blocking_http_parser(unsigned type) { reset(type); }

		blocking_http_parser(blocking_http_parser &&);
		blocking_http_parser & operator =(blocking_http_parser &&);

		blocking_http_parser(const blocking_http_parser &) = delete;
		blocking_http_parser & operator =(const blocking_http_parser &) = delete;
	};
}
