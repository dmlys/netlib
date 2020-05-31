#include <cstring>
#include <ext/itoa.hpp>
#include <ext/config.hpp>
#include <ext/net/http/nonblocking_http_writer.hpp>

namespace ext::net::http::http_server_utils
{
	bool nonblocking_http_writer::write_string(char *& first, char * last)
	{
		auto len = std::min<std::size_t>(m_string_last - m_string_first, last - first);
		first = std::copy(m_string_first, m_string_first + len, first);

		m_string_first += len;
		return m_string_first == m_string_last;
	}

	std::size_t nonblocking_http_writer::write_some_response(char * buffer, std::size_t bufsize)
	{
		auto * first = buffer;
		auto * last = buffer + bufsize;
		const std::string * name, * value;

		switch (m_state)
		{
			case 0:
				m_string_first = "HTTP/1.1 ";
				m_string_last = m_string_first + std::strlen(m_string_first);
				m_state = 1;
			case 1: // ver
				if (not write_string(first, last)) return first - buffer;

				assert(m_resp->http_code < 999);
				m_string_first = ext::unsafe_itoa(m_resp->http_code, m_respcode, 4, 10);
				m_string_last  = m_respcode + 4;
				m_respcode[3] = ' ';
				m_state = 2;
			case 2: // http code
				if (not write_string(first, last)) return first - buffer;

				m_string_first = m_resp->status.c_str();
				m_string_last  = m_string_first + std::strlen(m_string_first);
				m_state = 3;
			case 3: // status
				if (not write_string(first, last)) return first - buffer;

				m_string_first = "\r\n";
				m_string_last  = m_string_first + 2;
				m_state = 4;
			case 4: // crlf
				if (not write_string(first, last)) return first - buffer;

				m_cur_header = m_resp->headers.begin();

				for (; m_cur_header != m_resp->headers.end(); ++m_cur_header)
				{
					name = &m_cur_header->name;
					m_string_first = name->c_str();
					m_string_last  = m_string_first + name->size();
					m_state = 5;
			case 5: // write http header name
					if (not write_string(first, last)) return first - buffer;

					m_string_first = ": ";
					m_string_last  = m_string_first + std::strlen(m_string_first);
					m_state = 6;
			case 6: // write http header name
					if (not write_string(first, last)) return first - buffer;

					value = &m_cur_header->value;
					m_string_first = value->c_str();
					m_string_last  = m_string_first + value->size();
					m_state = 7;
			case 7: // write http header value
					if (not write_string(first, last)) return first - buffer;

					m_string_first = "\r\n";
					m_string_last  = m_string_first + 2;
					m_state = 8;
			case 8: // write crlf
					if (not write_string(first, last)) return first - buffer;
				}

				m_string_first = "\r\n";
				m_string_last  = m_string_first + 2;
				m_state = 9;
			case 9: // write headers end crlf
				if (not write_string(first, last)) return first - buffer;

				//m_string_first = m_resp->body.c_str();
				//m_string_last  = m_string_first + m_resp->body.size();
				//m_state = 10;
			//case 10:
				//if (not write_string(first, last)) return first - buffer;

				m_state = 10;
			case 10:
				return first - buffer;

			default:
				EXT_UNREACHABLE();
		}
	}

	std::size_t nonblocking_http_writer::write_some_request(char * buffer, std::size_t bufsize)
	{
		auto * first = buffer;
		auto * last = buffer + bufsize;
		const std::string * name, * value;

		switch (m_state)
		{
			case 0:
				m_string_first = m_req->method.c_str();
				m_string_last = m_string_first + m_req->method.size();
				m_state = 1;
			case 1: // write method
				if (not write_string(first, last)) return first - buffer;

				m_string_first = " ";
				m_string_last  = m_string_last + 1;
				m_state = 2;
			case 2: // write space
				if (not write_string(first, last)) return first - buffer;

				m_string_first = m_req->url.c_str();
				m_string_last  = m_string_first + m_req->url.size();
				m_state = 3;
			case 3: // write url
				if (not write_string(first, last)) return first - buffer;

				m_string_first = " HTTP/1.1\r\n";
				m_string_last  = m_string_first + std::strlen(m_string_first);
				m_state = 4;
			case 4: // write finish first line with ver and crlf
				if (not write_string(first, last)) return first - buffer;

				m_cur_header = m_resp->headers.begin();

				for (; m_cur_header != m_resp->headers.end(); ++m_cur_header)
				{
					name = &m_cur_header->name;
					m_string_first = name->c_str();
					m_string_last  = m_string_first + name->size();
					m_state = 5;
			case 5: // write http header name
					if (not write_string(first, last)) return first - buffer;

					m_string_first = ": ";
					m_string_last  = m_string_first + std::strlen(m_string_first);
					m_state = 6;
			case 6: // write http header name
					if (not write_string(first, last)) return first - buffer;

					value = &m_cur_header->value;
					m_string_first = value->c_str();
					m_string_last  = m_string_first + value->size();
					m_state = 7;
			case 7: // write http header value
					if (not write_string(first, last)) return first - buffer;

					m_string_first = "\r\n";
					m_string_last  = m_string_first + 2;
					m_state = 8;
			case 8: // write crlf
					if (not write_string(first, last)) return first - buffer;
				}

				m_string_first = "\r\n";
				m_string_last  = m_string_first + 2;
				m_state = 9;
			case 9: // write headers end crlf
				if (not write_string(first, last)) return first - buffer;

				//m_string_first = m_resp->body.c_str();
				//m_string_last  = m_string_first + m_resp->body.size();
				//m_state = 10;
			//case 10:
				//if (not write_string(first, last)) return first - buffer;

				m_state = 10;
			case 10:
				return first - buffer;

			default:
				EXT_UNREACHABLE();
		}
	}

	void nonblocking_http_writer::reset(const http_response * response)
	{
		m_method = &nonblocking_http_writer::write_some_response;
		m_state = 0;
		m_resp = response;

		m_string_last = m_string_first = nullptr;
		std::memset(m_respcode, 0, 4);
		m_cur_header = {};
	}

	void nonblocking_http_writer::reset(const http_request * request)
	{
		m_method = &nonblocking_http_writer::write_some_request;
		m_state = 0;
		m_req = request;

		m_string_last = m_string_first = nullptr;
		std::memset(m_respcode, 0, 4);
		m_cur_header = {};
	}

	void nonblocking_http_writer::reset(std::nullptr_t)
	{
		m_method = nullptr;
	}

	nonblocking_http_writer::nonblocking_http_writer(nonblocking_http_writer && other)
	    : m_method(std::exchange(other.m_method, nullptr)),
	      m_state(std::exchange(other.m_state, 0)),
	      m_req(std::exchange(other.m_req, nullptr)),
	      m_string_first(std::exchange(other.m_string_first, nullptr)),
	      m_string_last (std::exchange(other.m_string_last,  nullptr)),
	      m_cur_header(std::exchange(other.m_cur_header, {}))

	{
		std::memcpy(m_respcode, other.m_respcode, 4);
	}

	nonblocking_http_writer & nonblocking_http_writer::operator =(nonblocking_http_writer && other)
	{
		if (this != &other)
		{
			this->~nonblocking_http_writer();
			new (this) nonblocking_http_writer(std::move(other));
		}

		return *this;
	}

}
