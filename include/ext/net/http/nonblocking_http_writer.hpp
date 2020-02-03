#pragma once
#include <string>
#include <string_view>
#include <ext/net/http/http_types.hpp>

namespace ext::net::http
{
	/// simple non blocking http writer
	class nonblocking_http_writer
	{
	private:
		std::size_t (nonblocking_http_writer::*m_method)(char * data, std::size_t bufsize) = nullptr;
		unsigned m_state;
		char m_respcode[4];
		union {
			const http_response * m_resp;
			const http_request  * m_req;
		};
		const char * m_string_first;
		const char * m_string_last;
		header_map::const_iterator m_cur_header;

	private:
		bool write_string(char *& first, char * last);

		std::size_t write_some_request(char * buffer, std::size_t bufsize);
		std::size_t write_some_response(char * buffer, std::size_t bufsize);

	public:
		/// writes some data into given buffer, returns number of chars written,
		/// call finished to check if http entity completely written
		std::size_t write_some(char * buffer, std::size_t bufsize) { return (this->*m_method)(buffer, bufsize); }
		/// http entity completely written
		bool finished() { return m_state >= 11; }
		/// initialises writer for writing http response, after that write_some can be called
		void reset(const http_response * resp);
		/// initialises writer for writing http request, after that write_some can be called
		void reset(const http_request  * req );

	public:
		nonblocking_http_writer() = default;
		nonblocking_http_writer(const http_response * response) { reset(response); }
		nonblocking_http_writer(const http_request  * request ) { reset(request ); }

		nonblocking_http_writer(nonblocking_http_writer &&);
		nonblocking_http_writer & operator =(nonblocking_http_writer &&);

		nonblocking_http_writer(const nonblocking_http_writer &) = delete;
		nonblocking_http_writer & operator =(const nonblocking_http_writer &) = delete;
	};
}
