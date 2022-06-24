#include <ext/net/http/cors_filter.hpp>
#include <ext/log/logging_macros.hpp>

namespace ext::net::http
{
	void cors_filter::postfilter(http_server_control & control) const
	{
		auto & req = control.request();
		auto & resp = control.response();
		auto origin_header = get_header(req.headers, "Origin");
		if (not origin_header) return;

		//set_header(resp.headers, "Vary", "Origin");
		set_header(resp.headers,"Access-Control-Allow-Origin", origin_header.value);
	}

	void cors_filter::prefilter(http_server_control & control) const
	{
		auto & req = control.request();
		if (req.method != "OPTIONS") return;

		auto origin_header = get_header(req.headers, "Origin");
		if (not origin_header) return;

		EXTLOG_TRACE_STR(m_logger, "cors_handler: answering to OPTIONS http request");
		ext::net::http::http_response opts_resp;
		opts_resp.http_code = 204;
		opts_resp.status = "No Content";

		auto ac_request_method  = get_header_value(req.headers, "Access-Control-Request-Method");
		auto ac_request_headers = get_header_value(req.headers, "Access-Control-Request-Headers");
		
		set_header(opts_resp.headers, "Access-Control-Allow-Origin", origin_header.value);
		set_header(opts_resp.headers, "Access-Control-Allow-Methods", ac_request_method);
		set_header(opts_resp.headers, "Access-Control-Allow-Headers", ac_request_headers);
		
		set_header(opts_resp.headers, "Access-Control-Max-Age", "1800");
		set_header(opts_resp.headers, "Vary", "Origin");

		control.override_response(std::move(opts_resp));
	}
}
