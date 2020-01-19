#pragma once
#ifdef EXT_ENABLE_CPPZLIB
#include <ext/net/http/http_types.hpp>
#include <ext/net/http/http_server_filter.hpp>

namespace ext::net::http
{
	/// simple zlib filter:
	///  * deflating request body if request Content-Encoding = gzip or deflate
	///  * inflating response body if request Accept-Encoding specifies gzip or deflate
	class zlib_filter : public http_pre_filter, public http_post_filter
	{
		mutable std::stringstream m_parsing_stream;
		unsigned m_order = default_order;

	public:
		void set_order(unsigned order) { m_order = order; }
		unsigned preorder() const noexcept override { return m_order; }
		unsigned postorder() const noexcept override { return m_order; }

	protected:
		double parse_weight(std::string_view str) const;
		double extract_weight(std::string_view field, std::string_view name, double defval) const;

		// gzip_weight, deflate_weight
		auto parse_accept_encoding(std::string_view accept_encoding_field) const -> std::tuple<double, double>;
		std::string inflate(const std::string & data) const;
		std::string deflate(const std::string & data, bool deflate) const;

	public:
		virtual auto prefilter(ext::net::http::http_request & req) const -> std::optional<ext::net::http::http_response> override;
		virtual void postfilter(ext::net::http::http_request & req, ext::net::http::http_response & resp) const override;
	};
}
#endif // EXT_ENABLE_CPPZLIB
