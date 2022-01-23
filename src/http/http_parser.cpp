#include <ext/net/http/http_parser.hpp>

namespace ext::net::http
{
	int parse_http_response(http_parser & parser, std::streambuf & sb, std::string & response_body)
	{
		parse_http_body(parser, sb, response_body);
		return parser.http_code();
	}

	int parse_http_response(http_parser & parser, std::istream & is, std::string & response_body)
	{
		return parse_http_response(parser, *is.rdbuf(), response_body);
	}

	int parse_http_response(std::streambuf & sb, std::string & response_body)
	{
		http_parser parser(http_parser::response);
		return parse_http_response(parser, sb, response_body);
	}

	int parse_http_response(std::istream & is, std::string & response_body)
	{
		return parse_http_response(*is.rdbuf(), response_body);
	}


	void parse_http_request(http_parser & parser, std::streambuf & sb, std::string & method, std::string & url, std::string & request_body)
	{
		parse_http_body(parser, sb, request_body, &url);
		method = parser.http_method();
	}

	void parse_http_request(http_parser & parser, std::istream & is, std::string & method, std::string & url, std::string & request_body)
	{
		return parse_http_request(parser, *is.rdbuf(), method, url, request_body);
	}

	void parse_http_request(std::streambuf & sb, std::string & method, std::string & url, std::string & request_body)
	{
		http_parser parser(http_parser::request);
		parse_http_request(parser, sb, method, url, request_body);
	}

	void parse_http_request(std::istream & is, std::string & method, std::string & url, std::string & request_body)
	{
		return parse_http_request(*is.rdbuf(), method, url, request_body);
	}
}

#include <ext/net/http/http_parser_impl.hpp>

template void ext::net::http::parse_http_body<std::string>(http_parser & parser, std::streambuf & sb, std::string & body, std::string * status_or_url);
template void ext::net::http::parse_http_body<std::string>(http_parser & parser, std::istream   & is, std::string & body, std::string * status_or_url);

template void ext::net::http::parse_http_body<std::vector<char>>(http_parser & parser, std::streambuf & sb, std::vector<char> & body, std::string * status_or_url);
template void ext::net::http::parse_http_body<std::vector<char>>(http_parser & parser, std::istream   & is, std::vector<char> & body, std::string * status_or_url);
