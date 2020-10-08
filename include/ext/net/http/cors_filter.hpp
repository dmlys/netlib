#pragma once
#include <ext/net/http/http_types.hpp>
#include <ext/net/http/http_server_filter.hpp>

namespace ext::net::http
{
	/// filter for handling CORS requests(Cross-Origin Resource Sharing)
	class cors_filter : public http_prefilter, public http_postfilter
	{
		unsigned m_order = default_order - 2;

	public:
		void set_order(unsigned order) { m_order = order; }
		unsigned preorder() const noexcept override { return m_order; }
		unsigned postorder() const noexcept override { return m_order; }

	public:
		virtual void postfilter(http_server_filter_control & control) const override;
		virtual void prefilter(http_server_filter_control & control) const override;
	};
}
