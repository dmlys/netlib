#pragma once
#include <memory>
#include <string>
#include <utility>

#include <boost/config.hpp>
#include <ext/config.hpp>
#include "http_parser.h"

namespace ext {
namespace netlib
{
	/// http_parser based parser.
	/// additionally supports gzip, zlib, raw deflate Transfer-Encodings
	/// parses to internal buffer, that can be accessed
	class http_response_parser
	{
	public:
		enum state_type : unsigned
		{
			header_field, header_value,
			body, finished,
			start_state = header_field
		};

		state_type m_state;
		bool m_deflated;

		http_parser m_parser;
		http_parser_settings m_settings;

		union
		{
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
		
	private: /// others
		BOOST_NORETURN static void throw_parser_error(const http_parser * parser);
		BOOST_NORETURN static void throw_stream_error();

	private:
		static http_response_parser & get_this(http_parser * parser) { return *static_cast<http_response_parser *>(parser->data); }

		// http_parser callbacks
		static int on_message_complete(http_parser * parser);
		static int on_header_field(http_parser * parser, const char * data, size_t len);
		static int on_header_value(http_parser * parser, const char * data, size_t len);
		static int on_headers_complete(http_parser * parser);
		static int on_body(http_parser * parser, const char * data, size_t len);
		
		void init_parser(http_parser * parser, http_parser_settings * settings);
		void on_parsed_header(const std::string & name, const std::string & value);
		
	private:
		std::size_t execute(const char * input, std::size_t size)
		{ return http_parser_execute(&m_parser, &m_settings, input, size); }

	public: /// main process methods
		/// resets state of a parser and prepares it for parsing a message
		void reset();
		bool headers_parsed() const { return m_state >= body; }
		bool message_parsed() const { return m_state == finished; }
		bool deflated() const { return m_deflated; }

		bool parse_header(std::istream & is, std::string &, std::string &);
		bool parse_body(std::istream & is, const char *& buffer, std::size_t & buff_size);
		
		int http_code() const { return m_parser.status_code; }
		/// can be useful for error and some other info extracting
		const http_parser & parser() const { return m_parser; }

	public:
		http_response_parser() { reset(); }
		http_response_parser(const http_response_parser &);
		http_response_parser & operator =(const http_response_parser &);
	};


	int parse_http_response(std::istream & is, std::string & response_body);
}}
