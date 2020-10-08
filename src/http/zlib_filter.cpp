#ifdef EXT_ENABLE_CPPZLIB
#include <ext/stream_filtering/zlib.hpp>
#include <ext/net/http/zlib_filter.hpp>
#include <ext/net/http/parse_header.hpp>

#include <locale>
#include <algorithm>
#include <charconv>
#include <fmt/format.h>
#include <ext/cppzlib.hpp>
#include <ext/library_logger/logging_macros.hpp>

namespace ext::net::http
{
	auto zlib_filter::parse_accept_encoding(std::string_view accept_encoding_field) const -> std::tuple<double, double>
	{
		double gzip_weight = 1.0, deflate_weight = 1.0;

		if (double weight = extract_weight(accept_encoding_field, "*", 1.0); weight > 0)
			gzip_weight = deflate_weight = weight;

		gzip_weight    = extract_weight(accept_encoding_field, "gzip", gzip_weight);
		deflate_weight = extract_weight(accept_encoding_field, "deflate", deflate_weight);

		return std::make_tuple(gzip_weight, deflate_weight);
	}
	
	void zlib_filter::prefilter(http_server_filter_control & control) const
	{
		auto & req = control.request();
		
		auto accept_encoding = get_header_value(req.headers, "Accept-Encoding");
		if (not accept_encoding.empty())
			control.set_property("zlib-filter::Accept-Encoding", std::string(accept_encoding));
		
		auto * hdr = find_header(req.headers, "Content-Encoding");
		if (not hdr) return;

		const auto & encoding = hdr->value;
		if (encoding == "gzip" or encoding == "deflate")
		{
			EXTLL_TRACE_FMT(m_logger, "zlib_filter: Found Content-Encoding = {}", encoding);
			control.request_filter_append(std::make_unique<ext::stream_filtering::zlib_inflate_filter>());
		}
		
		return;
	}

	void zlib_filter::postfilter(http_server_filter_control & control) const
	{
		auto & resp = control.response();
		// if already have encoding - do nothing
		auto * enc_hdr = find_header(resp.headers, "Content-Encoding");
		if (enc_hdr) return;

		// if body empty - do not gzip it
		auto body_size = size(resp.body).value_or(-1);
		if (not body_size) return;
		
		auto encoding = get_property<std::string>(control, "zlib-filter::Accept-Encoding");
		if (not encoding or encoding->empty()) return;

		EXTLL_TRACE_FMT(m_logger, "zlib_filter: Found Accept-Encoding = {}", *encoding);

		double gzip_weight, deflate_weight;
		std::tie(gzip_weight, deflate_weight) = parse_accept_encoding(*encoding);

		if (gzip_weight > 0 and gzip_weight >= deflate_weight)
		{
			set_header(resp.headers, "Content-Encoding", "gzip");
			auto zlib_filter = std::make_unique<ext::stream_filtering::zlib_deflate_filter>(zlib::deflate_stream(Z_DEFAULT_COMPRESSION, MAX_WBITS + 16));
			control.response_filter_append(std::move(zlib_filter));
		}
		else if (deflate_weight > 0)
		{
			set_header(resp.headers, "Content-Encoding", "deflate");
			auto zlib_filter = std::make_unique<ext::stream_filtering::zlib_deflate_filter>(zlib::deflate_stream(Z_DEFAULT_COMPRESSION, MAX_WBITS +  0));
			control.response_filter_append(std::move(zlib_filter));
		}
	}
}

#endif // EXT_ENABLE_CPPZLIB
