#pragma once
#include <cstddef>
#include <climits> // for CHAR_BIT
#include <string>
#include <utility> // for std::pair

#include <streambuf>
#include <istream>

#include <type_traits> // for aligned_storage
#include <boost/config.hpp>

// from http_parser.h
struct http_parser;
struct http_parser_settings;

namespace ext {
namespace netlib
{
	/// ::http_parser based parser.
	/// additionally supports gzip, zlib, raw deflate Transfer-Encodings
	/// parses to internal buffer, that can be accessed
	class http_response_parser
	{
	public:
		enum state_type : unsigned
		{
			status_state,
			header_field, header_value,
			body_state, finished,

			start_state = status_state
		};

		state_type m_state;
		bool m_deflated;

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
		std::aligned_storage_t<HTTP_PARSER_SETTINGS_SIZE / CHAR_BIT, alignof(void *)> m_settings_object;

		union
		{
			struct
			{
				std::string * m_status_val;
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
		BOOST_NORETURN static void throw_stream_error();

	private:
		static http_response_parser & get_this(::http_parser * parser) noexcept;

		      ::http_parser & get_parser()       noexcept;
		const ::http_parser & get_parser() const noexcept;

		      ::http_parser_settings & get_settings()       noexcept;
		const ::http_parser_settings & get_settings() const noexcept;

		// ::http_parser callbacks
		static int on_status(::http_parser * parser, const char * data, size_t len);
		static int on_status_complete(::http_parser * parser, const char * data, size_t len);
		static int on_header_field(::http_parser * parser, const char * data, size_t len);
		static int on_header_value(::http_parser * parser, const char * data, size_t len);
		static int on_headers_complete(::http_parser * parser);
		static int on_body(::http_parser * parser, const char * data, size_t len);
		static int on_message_complete(::http_parser * parser);
		
		void init_parser(::http_parser * parser, ::http_parser_settings * settings);
		void on_parsed_header(const std::string & name, const std::string & value);

	public: // main process methods
		/// resets state of a parser and prepares it for parsing a message
		void reset();
		bool status_parsed()  const noexcept { return m_state >  status_state; }
		bool headers_parsed() const noexcept { return m_state >= body_state; }
		bool message_parsed() const noexcept { return m_state == finished; }
		bool deflated()       const noexcept { return m_deflated; }

		bool parse_status(std::streambuf & sb, std::string & str);
		bool parse_header(std::streambuf & sb, std::string & name, std::string & value);
		bool parse_body(std::streambuf & sb, const char *& buffer, std::size_t & buff_size);

		bool parse_status(std::istream & is, std::string & str);
		bool parse_header(std::istream & is, std::string & name, std::string & value);
		bool parse_body(std::istream & is, const char *& buffer, std::size_t & buff_size);
		
		int http_code() const;
		/// can be useful for error and some other info extracting
		const ::http_parser & parser() const { return get_parser(); }

	public:
		http_response_parser() { reset(); }
		http_response_parser(const http_response_parser &);
		http_response_parser & operator =(const http_response_parser &);
	};

	void parse_trailing(http_response_parser & parser, std::streambuf & sb);
	void parse_trailing(http_response_parser & parser, std::istream & is);

	int parse_http_response(std::streambuf & sb, std::string & response_body);
	int parse_http_response(std::istream & is, std::string & response_body);
	int parse_http_response(http_response_parser & parser, std::streambuf & is, std::string & response_body);
	int parse_http_response(http_response_parser & parser, std::istream & is, std::string & response_body);

	std::pair<int, std::string> parse_http_response(std::streambuf & sb);
	std::pair<int, std::string> parse_http_response(std::istream & is);
	std::pair<int, std::string> parse_http_response(http_response_parser & parser, std::streambuf & sb);
	std::pair<int, std::string> parse_http_response(http_response_parser & parser, std::istream & is);


	inline std::pair<int, std::string> parse_http_response(std::streambuf & sb)
	{
		std::string answer;
		int code = parse_http_response(sb, answer);
		return {code, std::move(answer)};
	}

	inline std::pair<int, std::string> parse_http_response(std::istream & is)
	{
		std::string answer;
		int code = parse_http_response(is, answer);
		return {code, std::move(answer)};
	}

	inline std::pair<int, std::string> parse_http_response(http_response_parser & parser, std::streambuf & sb)
	{
		std::string answer;
		int code = parse_http_response(parser, sb, answer);
		return {code, std::move(answer)};
	}

	inline std::pair<int, std::string> parse_http_response(http_response_parser & parser, std::istream & is)
	{
		std::string answer;
		int code = parse_http_response(parser, is, answer);
		return {code, std::move(answer)};
	}
}}
