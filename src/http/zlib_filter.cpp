#ifdef EXT_ENABLE_CPPZLIB
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
	double zlib_filter::parse_weight(std::string_view str) const
	{
		std::istringstream ss(std::string(str.data(), str.data() + str.size()));
		ss.imbue(std::locale::classic());

		double result = 0.0;
		ss >> result;

		return result;
	}

	double zlib_filter::extract_weight(std::string_view field, std::string_view name, double defval) const
	{
		std::string_view parstr, parval;
		if (not extract_header_value(field, name, parstr))
			return 0;

		if (extract_header_parameter(parstr, "q", parval))
			return parse_weight(parval);
		else
			return defval;
	}

	auto zlib_filter::parse_accept_encoding(std::string_view accept_encoding_field) const -> std::tuple<double, double>
	{
		double gzip_weight = 1, deflate_weight = 1;

		if (double weight = extract_weight(accept_encoding_field, "*", 1.0); weight > 0)
			gzip_weight = deflate_weight = weight;

		gzip_weight    = extract_weight(accept_encoding_field, "gzip", gzip_weight);
		deflate_weight = extract_weight(accept_encoding_field, "deflate", deflate_weight);

		return std::make_tuple(gzip_weight, deflate_weight);
	}


	std::string zlib_filter::inflate(const std::string & data) const
	{
		zlib::inflate_stream inflator {MAX_WBITS + 32};
		std::size_t sz = std::clamp<std::size_t>(1024, data.size(), 10 * 1024);
		std::string output;
		output.resize(sz);

		inflator.set_in(data.data(), data.size());
		inflator.set_out(output.data(), output.size());

		do
		{
			if (not inflator.avail_out())
			{
				auto newsz = sz * 3 / 2;
				output.resize(newsz);
				inflator.set_out(output.data() + sz, newsz - sz);
				sz = newsz;
			}

			int res = ::inflate(inflator, Z_NO_FLUSH);
			switch (res)
			{
			    case Z_OK: break;

			    case Z_STREAM_END:
				    assert(not inflator.avail_in());
					break;

			    case Z_NEED_DICT:
			    case Z_BUF_ERROR:
			    case Z_ERRNO:
			    case Z_STREAM_ERROR:
			    case Z_DATA_ERROR:
			    case Z_MEM_ERROR:
			    case Z_VERSION_ERROR:
			    default:
				    zlib::throw_zlib_error(res, inflator);
			}
		} while (inflator.avail_in());

		output.resize(inflator.total_out());
		return output;
	}

	std::string zlib_filter::deflate(const std::string & data, bool gzip) const
	{
		zlib::deflate_stream deflator {Z_DEFAULT_COMPRESSION, MAX_WBITS + (gzip ? 16 : 0)};
		std::size_t sz = std::clamp<std::size_t>(1024, data.size(), 10 * 1024);
		std::string output;
		output.resize(sz);

		deflator.set_in(data.data(), data.size());
		deflator.set_out(output.data(), output.size());

		do
		{
			if (not deflator.avail_out())
			{
				auto newsz = sz * 3 / 2;
				output.resize(newsz);
				deflator.set_out(output.data() + sz, newsz - sz);
				sz = newsz;
			}

			int res = ::deflate(deflator, Z_NO_FLUSH);
			switch (res)
			{
				case Z_OK: break;

				case Z_STREAM_END:
					assert(not deflator.avail_in());
					break;

				case Z_NEED_DICT:
				case Z_BUF_ERROR:
				case Z_ERRNO:
				case Z_STREAM_ERROR:
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
				case Z_VERSION_ERROR:
				default:
					zlib::throw_zlib_error(res, deflator);
			}
		} while (deflator.avail_in());

		do
		{
			if (not deflator.avail_out())
			{
				auto newsz = sz * 3 / 2;
				output.resize(newsz);
				deflator.set_out(output.data() + sz, newsz - sz);
				sz = newsz;
			}

			int res = ::deflate(deflator, Z_FINISH);
			switch (res)
			{
				case Z_OK: break;

				case Z_STREAM_END:
					assert(not deflator.avail_in());
					break;

				case Z_NEED_DICT:
				case Z_BUF_ERROR:
				case Z_ERRNO:
				case Z_STREAM_ERROR:
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
				case Z_VERSION_ERROR:
				default:
					zlib::throw_zlib_error(res, deflator);
			}
		} while (deflator.avail_in());

		output.resize(deflator.total_out());
		return output;
	}

	auto zlib_filter::prefilter(ext::net::http::http_request & req) const -> std::optional<ext::net::http::http_response>
	{
		auto * hdr = find_header(req.headers, "Content-Encoding");
		if (not hdr) return std::nullopt;

		const auto & encoding = hdr->value;
		if (encoding == "gzip" or encoding == "deflate")
		{
			EXTLL_TRACE_FMT(m_logger, "zlib_filter: Found Content-Encoding = {}", encoding);
			req.body = inflate(req.body);
			remove_header(req.headers, "Content-Encoding");
		}

		return std::nullopt;
	}

	void zlib_filter::postfilter(ext::net::http::http_request & req, ext::net::http::http_response & resp) const
	{
		auto * hdr = find_header(resp.headers, "Accept-Encoding");
		if (not hdr) return;

		std::string_view encoding = hdr->value;
		EXTLL_TRACE_FMT(m_logger, "zlib_filter: Found Accept-Encoding = {}", encoding);

		double gzip_weight, deflate_weight;
		std::tie(gzip_weight, deflate_weight) = parse_accept_encoding(encoding);

		if (gzip_weight > 0 and gzip_weight >= deflate_weight)
		{
			set_header(resp.headers, "Content-Encoding", "gzip");
			resp.body = deflate(resp.body, true);
		}
		else if (deflate_weight > 0)
		{
			set_header(resp.headers, "Content-Encoding", "deflate");
			resp.body = deflate(resp.body, false);
		}
	}
}

#endif // EXT_ENABLE_CPPZLIB
