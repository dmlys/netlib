#include <ext/net/http/cors_filter.hpp>
#include <ext/library_logger/logging_macros.hpp>

namespace ext::net::http
{
	void cors_filter::postfilter(ext::net::http::http_request & req, ext::net::http::http_response & resp) const
	{
		auto origin_header = get_header(req.headers, "Origin");
		if (not origin_header) return;

		set_header(resp.headers, "Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
		set_header(resp.headers,"Access-Control-Allow-Origin", origin_header.value);
	}

	auto cors_filter::prefilter_headers(ext::net::http::http_request & req) const -> std::optional<ext::net::http::http_response>
	{
		if (req.method != "OPTIONS") return std::nullopt;

		auto origin_header = get_header(req.headers, "Origin");
		if (not origin_header) return std::nullopt;

		EXTLL_TRACE_STR(m_logger, "cors_handler: answering to OPTIONS http request");
		ext::net::http::http_response opts_resp;
		opts_resp.http_code = 200;
		opts_resp.status = "OK";
		opts_resp.conn_action = req.conn_action;

		set_header(opts_resp.headers, "Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers");
		set_header(opts_resp.headers, "Access-Control-Allow-Origin", origin_header.value);
		copy_headers(opts_resp.headers, req.headers, "Access-Control-Allow-Methods");
		copy_headers(opts_resp.headers, req.headers, "Access-Control-Allow-Headers");
		set_header(opts_resp.headers, "Access-Control-Max-Age", "1800");

		return opts_resp;
	}
}
