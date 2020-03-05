#pragma once
#include <ext/net/http/http_types.hpp>
#include <ext/net/http/http_server_filter.hpp>

namespace ext::net::http
{
	/// filter for handling CORS requests(Cross-Origin Resource Sharing)
	class cors_filter : public http_headers_prefilter, public http_post_filter
	{
		unsigned m_order = default_order - 2;

	public:
		void set_order(unsigned order) { m_order = order; }
		unsigned preorder_headers() const noexcept override { return m_order; }
		unsigned postorder() const noexcept override { return m_order; }

	public:
		virtual void postfilter(ext::net::http::http_request & req, ext::net::http::http_response & resp) const override;
		virtual auto prefilter_headers(ext::net::http::http_request & req) const -> std::optional<ext::net::http::http_response> override;
	};
}
