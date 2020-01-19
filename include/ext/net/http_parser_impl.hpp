#pragma once
#include <ext/config.hpp>
#include <ext/cppzlib.hpp>
#include <ext/range.hpp>
#include <ext/iostreams/streambuf.hpp>
#include <ext/net/http_parser.hpp>

namespace ext::net
{
	template <class Container>
	void http_parser::parse_http_body(std::streambuf & sb, Container & body, std::string * pstatus_url /* = nullptr */)
	{
		std::string name, value;
		const char * buffer;
		std::size_t len;
		std::string & status_url = pstatus_url ? *pstatus_url : value;

		while (parse_status(sb, status_url))
			continue;

		while (parse_header(sb, name, value))
			continue;

		if (deflated())
		{
#ifdef EXT_ENABLE_CPPZLIB
			std::size_t sz = std::max<std::size_t>(1024, body.capacity());
			sz = std::min<std::size_t>(10 * 1024, sz);
			sz = std::max<std::size_t>(sz, body.size());
			body.resize(sz);

			zlib::inflate_stream inflator {MAX_WBITS + 32};
			inflator.set_out(ext::data(body), body.size());

			while (parse_body(sb, buffer, len))
			{
				inflator.set_in(buffer, len);
				do {
					if (not inflator.avail_out())
					{
						auto newsz = sz * 3 / 2;
						body.resize(newsz);
						inflator.set_out(ext::data(body) + sz, newsz - sz);
						sz = newsz;
					}

					int res = ::inflate(inflator, Z_NO_FLUSH);
					switch (res)
					{
					    case Z_OK: break;

					    case Z_STREAM_END:
						    assert(not inflator.avail_in());
							if (parse_body(sb, buffer, len))
								throw std::runtime_error("inconsistent deflated stream, trailing data after Z_STREAM_END");

							goto finished;

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
			}

        finished:
			body.resize(inflator.total_out());
#else
			throw std::runtime_error("can't inflate compressed stream, ext::net::http_parser built without zlib support");
#endif
		}
		else
		{
			while (parse_body(sb, buffer, len))
				ext::append(body, buffer, buffer + len);
		}
	}

	template <class Container>
	void http_parser::parse_http_body(std::istream & is, Container & body, std::string * status_or_url)
	{
		return parse_http_body(*is.rdbuf(), body, status_or_url);
	}
}
