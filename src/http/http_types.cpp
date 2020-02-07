#include <ext/net/http/http_types.hpp>
#include <ext/itoa.hpp>
#include <algorithm>

namespace ext::net::http
{
	http_header_view::operator http_header() const
	{
		return {
			std::string(name.data(), name.size()),
			std::string(value.data(), value.size())
		};
	}

	http_header::operator http_header_view() const noexcept
	{
		return http_header_view {
			name,
			value
		};
	}

	void clear(http_request & request) noexcept
	{
		request.http_version = 11;
		request.method.clear();
		request.url.clear();
		request.body.clear();
		request.headers.clear();
		request.conn_action = def;
	}

	void clear(http_response & response) noexcept
	{
		response.http_version = 11;
		response.http_code = 404;
		response.status.clear();
		response.body.clear();
		response.headers.clear();
		response.conn_action = def;
	}


	inline static std::streambuf & operator <<(std::streambuf & streambuf, char ch)
	{
		streambuf.sputc(ch);
		return streambuf;
	}

	inline static std::streambuf & operator <<(std::streambuf & streambuf, std::string_view str)
	{
		streambuf.sputn(str.data(), str.size());
		return streambuf;
	}

	static std::streambuf & operator <<(std::streambuf & streambuf, std::size_t num)
	{
		ext::itoa_buffer<decltype(num)> buffer;
		streambuf << ext::itoa(num, buffer);
		return streambuf;
	}

	static std::streambuf & operator <<(std::streambuf & streambuf, int num)
	{
		ext::itoa_buffer<decltype(num)> buffer;
		streambuf << ext::itoa(num, buffer);
		return streambuf;
	}

	void write_http_request(std::streambuf & os, const http_request & request, bool with_body)
	{
		os << request.method << ' ' << request.url << ' ';
		os << "HTTP/1.1\r\n";
		//os << "HTTP/" << (request.http_version / 10) << '.' << (request.http_version % 10);
		//os << '\r' << '\n';

		for (auto [name, value] : request.headers)
			os << name << ':' << ' ' << value << '\r' << '\n';

		if (with_body)
		{
			os << '\r' << '\n';
			os << request.body;
		}
	}

	void write_http_response(std::streambuf & os, const http_response & response, bool with_body)
	{
		os << "HTTP/1.1 " << response.http_code << ' ' << response.status << '\r' << '\n';

		for (auto [name, value] : response.headers)
			os << name << ':' << ' ' << value << '\r' << '\n';

		if (with_body)
		{
			os << '\r' << '\n';
			os << response.body;
		}
	}
}
