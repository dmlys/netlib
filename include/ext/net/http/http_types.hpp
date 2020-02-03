#pragma once
#include <ostream>
#include <string>
#include <string_view>
#include <unordered_map>

namespace ext::net::http
{
	using header_map = std::unordered_map<std::string, std::string>;

	/// what should be done with connection: close, keep-alive, or some default action
	enum connection_type : unsigned
	{
		/// default(def): close or keep_alive, which can be choosed based on some heuristics.
		/// For http_server that can mean choose response action based on request action.
		def = 0,
		close = 1,
		keep_alive = 2,
	};

	struct http_request
	{
		int http_version = 11;
		std::string method;
		std::string url;
		std::string body;
		header_map headers;

		connection_type conn = def;
	};

	struct http_response
	{
		int http_code = 0;
		std::string status;
		std::string body;
		header_map headers;

		connection_type conn = def;
	};

	void write_http_request (std::streambuf & os, const http_request  & request,  bool with_body = true);
	void write_http_response(std::streambuf & os, const http_response & response, bool with_body = true);

	inline void write_http_request (std::ostream & os, const http_request  & request,  bool with_body = true) { return write_http_request(*os.rdbuf(), request, with_body);   }
	inline void write_http_response(std::ostream & os, const http_response & response, bool with_body = true) { return write_http_response(*os.rdbuf(), response, with_body); }

	inline std::ostream & operator <<(std::ostream & os, const http_request  & request)  { write_http_request(os, request);   return os; }
	inline std::ostream & operator <<(std::ostream & os, const http_response & response) { write_http_response(os, response); return os; }
}

namespace ext::net
{
	using http::http_request;
	using http::http_response;
}
