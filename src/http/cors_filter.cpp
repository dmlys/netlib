#include <ext/net/http/cors_filter.hpp>
#include <ext/net/http/http_server_logging_helpers.hpp>

#include <ext/functors/ctpred.hpp>
#include <ext/strings/aci_string.hpp>
#include <ext/net/parse_url.hpp>

#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

namespace ext::net::http
{
	bool cors_filter::is_allowed(const http_request & req) const
	{
		if (m_allow_any)
			return true;
		
		auto origin_header = get_header(req.headers, "Origin");
		if (not origin_header)
			return false;
		
		for (const auto & allowed : m_allowed_cors)
			if (origin_header.value == allowed)
				return true;
		
		return false;
	}
	
	bool cors_filter::is_allowed(std::string_view origin_header) const
	{
		if (m_allow_any)
			return true;
		
		if (origin_header.empty())
			return false;
		
		for (const auto & allowed : m_allowed_cors)
			if (origin_header == allowed)
				return true;
		
		return false;
	}
	
	auto cors_filter::make_allowed_response(const http_headers_vector & headers) const -> http_response
	{
		http_response opts_resp;
		opts_resp.http_code = 204;
		opts_resp.status = "No Content";
	
		auto ac_request_method  = get_header_value(headers, "Access-Control-Request-Method");
		auto ac_request_headers = get_header_value(headers, "Access-Control-Request-Headers");
		auto origin_header      = get_header_value(headers, "Origin");
		
		set_header(opts_resp.headers, "Access-Control-Allow-Origin", m_allow_any ? "*" : origin_header);
		set_header(opts_resp.headers, "Access-Control-Allow-Methods", ac_request_method);
		set_header(opts_resp.headers, "Access-Control-Allow-Headers", ac_request_headers);
		
		set_header(opts_resp.headers, "Access-Control-Max-Age", "1800");
		set_header(opts_resp.headers, "Vary", "Origin");
		
		return opts_resp;
	}
	
	auto cors_filter::make_allowed_response(const http_request & req) const -> http_response
	{
		return make_allowed_response(req.headers);
	}
	
	auto cors_filter::make_disallowed_response() const -> http_response
	{
		http_response opts_resp;
		opts_resp.http_code = 204;
		opts_resp.status = "No Content";
		
		set_header(opts_resp.headers, "Vary", "Origin");
		
		return opts_resp;
	}
	
	auto cors_filter::make_forbidden_response() const -> http_response
	{
		http_response resp;
		resp.http_code = 403;
		resp.status = "Forbidden";
		resp.body = "Forbidden by CORS";
		set_header(resp.headers, "Content-Type", "text/plain");
		
		return resp;
	}
	
	void cors_filter::prefilter(http_server_control & control) const
	{
		auto & req = control.request();
		if (not is_allowed(req))
		{
			EXTLOG_INFO(m_logger, "http_cors_filter: Request is forbidden by CORS");
			control.override_response(make_disallowed_response());
			return;
		}
		
		if (req.method != "OPTIONS")
			return;
		
		auto origin_header = get_header(req.headers, "Origin");
		if (not origin_header)
			return;
		
		EXTLOG_TRACE(m_logger, "http_cors_filter: answering to OPTIONS http request");
		auto opts_resp = make_allowed_response(req);
		control.override_response(std::move(opts_resp));
	}
	
	void cors_filter::postfilter(http_server_control & control) const
	{
		auto & req = control.request();
		auto & resp = control.response();
			
		auto origin_header = get_header(req.headers, "Origin");
		if (not origin_header)
			return;
		
		set_header(resp.headers, "Vary", "Origin");
		set_header(resp.headers, "Access-Control-Allow-Origin", m_allow_any ? "*" : origin_header.value);
	}
	
	
	auto cors_filter::parse_cors_list(const std::string & cors_list_str) const -> std::vector<std::string>
	{
		std::vector<std::string> result;
		boost::regex hostname_regex(R"([^\\/?#@\s:]+(?:\:\d+)?)");
		
		EXTLOG_TRACE_FMT(m_logger, "http_cors_filter: parsing CORS list: {}", cors_list_str);
		
		std::vector<std::string> cors_items;
		boost::algorithm::split(cors_items, cors_list_str, boost::algorithm::is_any_of(" \t\n\r,;"), boost::token_compress_on);
		
		for (auto & name : cors_items)
		{
			if (name.empty())
				continue;
			
			ext::net::parsed_url parsed_url;
			if (not parse_url(name, parsed_url))
			{
				EXTLOG_WARN_FMT(m_logger, "http_cors_filter: Bad CORS name = {}, ignored", name);
				continue;
			}
			
			if (not parsed_url.schema.empty() and not parsed_url.host.empty())
			{
				std::string allowed_cors = parsed_url.schema + "://" + parsed_url.host;
				if (not parsed_url.port.empty())
					allowed_cors.append(":").append(parsed_url.port);
				
				EXTLOG_TRACE_FMT(m_logger, "http_cors_filter: adding CORS item = {}", allowed_cors);
				result.push_back(std::move(allowed_cors));
			}
			else if (boost::regex_match(name, hostname_regex))
			{
				std::string allowed_cors;
				
				allowed_cors = "https://" + name;
				EXTLOG_TRACE_FMT(m_logger, "http_cors_filter: adding CORS item = {}", allowed_cors);
				result.push_back(std::move(allowed_cors));
				
				allowed_cors = "http://" + name;
				EXTLOG_TRACE_FMT(m_logger, "http_cors_filter: adding CORS item = {}", allowed_cors);
				result.push_back(std::move(allowed_cors));
			}
			else
			{
				EXTLOG_WARN_FMT(m_logger, "http_cors_filter: Bad CORS name = {}, ignored", name);
			}
		}
		
		return result;
	}
	
	void cors_filter::set_cors_list(const std::string & allowed_cors_list)
	{
		m_allow_any = false;
		m_allowed_cors = parse_cors_list(allowed_cors_list);
	}
	
	cors_filter::cors_filter(bool allow_any)
		: m_allow_any(allow_any)
	{
		
	}
	
	cors_filter::cors_filter(const std::string & allowed_cors_list)
		: m_allow_any(false)
	{
		m_allowed_cors = parse_cors_list(allowed_cors_list);
		//m_allow_all = m_allowed_cors.empty();
	}
}
