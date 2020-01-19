#include <ext/net/http/cors_filter.hpp>
#include <ext/library_logger/logging_macros.hpp>

namespace ext::net::http
{
	void cors_filter::postfilter(ext::net::http::http_request & req, ext::net::http::http_response & resp) const
	{
		if (not req.headers.count("Origin")) return;

		resp.headers["Vary"] = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";
		resp.headers["Access-Control-Allow-Origin"] = req.headers["Origin"];
	}

	auto cors_filter::prefilter(ext::net::http::http_request & req) const -> std::optional<ext::net::http::http_response>
	{
		if (req.method != "OPTIONS") return std::nullopt;
		if (req.headers.count("Origin") == 0) return std::nullopt;

		EXTLL_TRACE_STR(m_logger, "cors_handler: answering to OPTIONS http request");
		ext::net::http::http_response resp;
		resp.http_code = 200;
		resp.status = "OK";
		resp.conn = req.conn;

		resp.headers["Vary"] = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";
		resp.headers["Access-Control-Allow-Origin" ] = req.headers["Origin"];
		resp.headers["Access-Control-Allow-Methods"] = req.headers["Access-Control-Request-Method"];
		resp.headers["Access-Control-Allow-Headers"] = req.headers["Access-Control-Request-Headers"];
		resp.headers["Access-Control-Max-Age"] = "1800";

		return resp;
	}
}
