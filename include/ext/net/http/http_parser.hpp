#pragma once
#include <ext/net/http/parse_header.hpp>
#include <ext/net/http/blocking_http_parser.hpp>

namespace ext::net::http
{
	using http_parser = http::blocking_http_parser;


	/// parses http body, similar to http_parser::parse_body, but already does loop internally and also supports zlib, inflating if needed
	template <class Container> void parse_http_body(http_parser & parser, std::streambuf & sb, Container & body, std::string * status_or_url = nullptr);
	template <class Container> void parse_http_body(http_parser & parser, std::istream   & is, Container & body, std::string * status_or_url = nullptr);
	// parse_http_body implementation is defined http_parser_impl.hpp.
	// This library provides explicit instantiations for std::string and std::vector<char>,
	// others can be explicitly instantiated by hand
	

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
	/*                     inline request impl                              */
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

	/************************************************************************/
	/*         parse_http_body explicit instantiation declarations          */
	/************************************************************************/
	extern template void parse_http_body<std::string>(http_parser & parser, std::streambuf & sb, std::string & body, std::string * status_or_url);
	extern template void parse_http_body<std::string>(http_parser & parser, std::istream   & is, std::string & body, std::string * status_or_url);
	
	extern template void parse_http_body<std::vector<char>>(http_parser & parser, std::streambuf & sb, std::vector<char> & body, std::string * status_or_url);
	extern template void parse_http_body<std::vector<char>>(http_parser & parser, std::istream   & is, std::vector<char> & body, std::string * status_or_url);
}
