#pragma once
#ifdef EXT_ENABLE_CPPZLIB
#include <ext/net/http/http_types.hpp>
#include <ext/net/http/http_server_filter.hpp>

namespace ext::net::http
{
	/// simple zlib filter:
	///  * deflating request body if request Content-Encoding = gzip or deflate
	///  * inflating response body if request Accept-Encoding specifies gzip or deflate
	class zlib_filter : public http_prefilter, public http_postfilter
	{
		mutable std::stringstream m_parsing_stream;
		unsigned m_order = default_order;

	public:
		void set_order(unsigned order) { m_order = order; }
		unsigned preorder() const noexcept override { return m_order; }
		unsigned postorder() const noexcept override { return m_order; }

	protected:
		// gzip_weight, deflate_weight
		auto parse_accept_encoding(std::string_view accept_encoding_field) const -> std::tuple<double, double>;

	public:
		virtual void prefilter(http_server_control & control) const override;
		virtual void postfilter(http_server_control & control) const override;
	};
}
#endif // EXT_ENABLE_CPPZLIB
