#pragma once
#include <cstddef>
#include <climits> // for CHAR_BIT
#include <string>
#include <string_view>
#include <tuple>

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
	class http_parser
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
		state_type m_state;
		unsigned m_deflated : 1;
		unsigned m_type     : 2;

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
		static http_parser & get_this(::http_parser * parser) noexcept;

		      ::http_parser & get_parser()       noexcept;
		const ::http_parser & get_parser() const noexcept;

		      ::http_parser_settings & get_settings()       noexcept;
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
		
		void init_parser(::http_parser * parser, ::http_parser_settings * settings);
		void on_parsed_header(const std::string & name, const std::string & value);

	public: // main process methods
		/// resets state of a parser and prepares it for parsing a message
		void reset() { reset(m_type); }
		void reset(unsigned type);

		bool status_parsed()  const noexcept { return m_state >  status_state; }
		bool url_parsed()     const noexcept { return m_state >  url_state; }
		bool headers_parsed() const noexcept { return m_state >= body_state; }
		bool message_parsed() const noexcept { return m_state == finished; }

		bool deflated()       const noexcept { return m_deflated; }
		void force_defalted()       noexcept { m_deflated = true; }

		bool parse_status(std::streambuf & sb, std::string & str);
		bool parse_url(std::streambuf & sb, std::string & str);
		bool parse_header(std::streambuf & sb, std::string & name, std::string & value);
		bool parse_body(std::streambuf & sb, const char *& buffer, std::size_t & buff_size);

		bool parse_status(std::istream & is, std::string & str);
		bool parse_url(std::istream & is, std::string & str);
		bool parse_header(std::istream & is, std::string & name, std::string & value);
		bool parse_body(std::istream & is, const char *& buffer, std::size_t & buff_size);

	public:
		/// parses http body, similar to parse_body, but already does loop internally and also supports zlib, inflating if needed
		void parse_http_body(std::streambuf & sb, std::string & body, std::string * status_or_url = nullptr);
		void parse_http_body(std::istream   & is, std::string & body, std::string * status_or_url = nullptr);

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
		http_parser() : http_parser(request | response) {}
		http_parser(unsigned type) { reset(type); }

		http_parser(http_parser &&);
		http_parser & operator =(http_parser &&);

		http_parser(const http_parser &) = delete;
		http_parser & operator =(const http_parser &) = delete;
	};



	int parse_http_response(std::streambuf & sb, std::string & response_body);
	int parse_http_response(std::istream   & is, std::string & response_body);
	int parse_http_response(http_parser & parser, std::streambuf & is, std::string & response_body);
	int parse_http_response(http_parser & parser, std::istream   & is, std::string & response_body);

	std::tuple<int, std::string> parse_http_response(std::streambuf & sb);
	std::tuple<int, std::string> parse_http_response(std::istream & is);
	std::tuple<int, std::string> parse_http_response(http_parser & parser, std::streambuf & sb);
	std::tuple<int, std::string> parse_http_response(http_parser & parser, std::istream & is);



	void parse_http_request(std::streambuf & sb, std::string & method, std::string & url, std::string & request_body);
	void parse_http_request(std::istream   & is, std::string & method, std::string & url, std::string & request_body);
	void parse_http_request(http_parser & parser, std::streambuf & is, std::string & method, std::string & url, std::string & request_body);
	void parse_http_request(http_parser & parser, std::istream   & is, std::string & method, std::string & url, std::string & request_body);

	std::tuple<std::string, std::string, std::string> parse_http_request(std::streambuf & sb);
	std::tuple<std::string, std::string, std::string> parse_http_request(std::istream   & is);
	std::tuple<std::string, std::string, std::string> parse_http_request(http_parser & parser, std::streambuf & is);
	std::tuple<std::string, std::string, std::string> parse_http_request(http_parser & parser, std::istream   & is);

	/// parses regular HTTP header(MIME headers not supported). Understands HTTP header parameters.
	/// returns true if header_str has more input, false if header_str depleted.
	/// parsing examples:
	///   Content-Type: text/xml  -> [("Content-Type", "text/xml")]
	///   some string             -> [("", "some string")]
	///   some string; name=test  -> [("", "some string"), ("name", "test")]
	///   name: value; par=val    -> [("name", "value"), ("par", "val")]
	///
	/// Typical usage:
	///   while(parse_http_header(header_str, name, val))
	///   {
	///       do something with name and val
	///   }
	bool parse_http_header(std::string & header_str, std::string & name, std::string & value); // can throw bad_alloc on string assignment
	bool parse_http_header(std::string_view & header_str, std::string_view & name, std::string_view & value) noexcept;

	/************************************************************************/
	/*                     inline response impl                             */
	/************************************************************************/
	inline std::tuple<int, std::string> parse_http_response(std::streambuf & sb)
	{
		std::string answer;
		int code = parse_http_response(sb, answer);
		return {code, std::move(answer)};
	}

	inline std::tuple<int, std::string> parse_http_response(std::istream & is)
	{
		std::string answer;
		int code = parse_http_response(is, answer);
		return {code, std::move(answer)};
	}

	inline std::tuple<int, std::string> parse_http_response(http_parser & parser, std::streambuf & sb)
	{
		std::string answer;
		int code = parse_http_response(parser, sb, answer);
		return {code, std::move(answer)};
	}

	inline std::tuple<int, std::string> parse_http_response(http_parser & parser, std::istream & is)
	{
		std::string answer;
		int code = parse_http_response(parser, is, answer);
		return {code, std::move(answer)};
	}

	/************************************************************************/
	/*                     inline request impl                             */
	/************************************************************************/
	inline std::tuple<std::string, std::string, std::string> parse_http_request(std::streambuf & sb)
	{
		std::string method, url, body;
		parse_http_request(sb, method, url, body);
		return {std::move(method), std::move(url), std::move(body)};
	}

	inline std::tuple<std::string, std::string, std::string> parse_http_request(std::istream & is)
	{
		std::string method, url, body;
		parse_http_request(is, method, url, body);
		return {std::move(method), std::move(url), std::move(body)};
	}

	inline std::tuple<std::string, std::string, std::string> parse_http_request(http_parser & parser, std::streambuf & sb)
	{
		std::string method, url, body;
		parse_http_request(parser, sb, method, url, body);
		return {std::move(method), std::move(url), std::move(body)};
	}

	inline std::tuple<std::string, std::string, std::string> parse_http_request(http_parser & parser, std::istream & is)
	{
		std::string method, url, body;
		parse_http_request(parser, is, method, url, body);
		return {std::move(method), std::move(url), std::move(body)};
	}
}}
