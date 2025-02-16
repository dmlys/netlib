#pragma once
#include <string>
#include <vector>

#include <ext/net/http/http_types.hpp>
#include <ext/net/http/http_server_filter.hpp>

namespace ext::net::http
{
	/// filter for handling CORS requests(Cross-Origin Resource Sharing)
	class cors_filter : public http_prefilter, public http_postfilter
	{
		std::vector<std::string> m_allowed_cors;
		bool m_allow_any = false;
		
	public:
		bool is_allowed(const http_request & req) const;
		bool is_allowed(std::string_view origin_header) const;
		
		auto make_allowed_response(const http_request & req) const -> http_response;
		auto make_allowed_response(const http_headers_vector & headers) const -> http_response;
		auto make_disallowed_response() const -> http_response;
		auto make_forbidden_response() const -> http_response;
		
		auto parse_cors_list(const std::string & cors_names) const -> std::vector<std::string>;
		
	public:
		unsigned preorder() const noexcept override { return default_order - 2; }
		unsigned postorder() const noexcept override { return default_order - 2; }
	
	public:
		virtual void postfilter(http_server_control & control) const override;
		virtual void prefilter(http_server_control & control) const override;
		
	public:
		void set_cors_list(const std::string & allowed_cors_list);
		
	public:
		cors_filter(bool allow_any);
		cors_filter(const std::string & allowed_cors_list);
	};	
}
