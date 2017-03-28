#include <ext/netlib/http_response_stream.hpp>

namespace ext {
namespace netlib
{
	auto http_response_streambuf::underflow() -> int_type
	{
		if (not m_reader) return traits_type::eof();
		return (this->*m_reader)();
	}

	auto http_response_streambuf::underflow_normal() -> int_type
	{
		char * ptr;
		std::size_t len;
		if (not m_parser.parse_body(*m_source, const_cast<const char *&>(ptr), len) or len == 0)
			return traits_type::eof();
		
		setg(ptr, ptr, ptr + len);
		return traits_type::to_int_type(*ptr);
	}

	auto http_response_streambuf::underflow_deflated() -> int_type
	{
#ifdef EXT_ENABLE_CPPZLIB
		const char * buffer;
		std::size_t buflen;

		for (;;)
		{
			if (not m_inflator.avail_in())
			{

				if (not m_parser.parse_body(*m_source, buffer, buflen))
					return traits_type::eof();

				m_inflator.set_in(buffer, buflen);
			}

			char * ptr = m_buffer.get();
			m_inflator.set_out(ptr, m_buffer_size);

			int res = ::inflate(m_inflator, Z_NO_FLUSH);
			auto next_out = reinterpret_cast<char *>(m_inflator.next_out());
			switch (res)
			{
				case Z_OK:
					// if no output was generated - we need no consume more input
					if (ptr == next_out) continue;
					break;
					
				case Z_STREAM_END:					
					// This call is important, it will consume any trailing characters, 
					// like newline, and complete http parsing(and still return false),
					// otherwise - you can read not a full http message and whoever parses next - will get trailing data.
					if (m_parser.parse_body(*m_source, buffer, buflen))
						throw std::runtime_error("inconsistent deflated stream, trailing data after Z_STREAM_END");

					// got stream end, no data was uncompressed - just eof
					if (ptr == next_out) return traits_type::eof();
					break;

				case Z_NEED_DICT:
				case Z_BUF_ERROR:
				case Z_ERRNO:
				case Z_STREAM_ERROR:
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
				case Z_VERSION_ERROR:
				default:
					zlib::throw_zlib_error(res, m_inflator);
			}

			setg(ptr, ptr, next_out);
			return traits_type::to_int_type(*ptr);
		}
#else
		throw std::runtime_error("can't inflate compressed stream, http_response_streambuf built without zlib support");
		return traits_type::eof();
#endif
	}
	
	void http_response_streambuf::init()
	{
		std::string name, val;
		while (m_parser.parse_header(*m_source, name, val));

		if (m_parser.deflated())
		{
			m_buffer = std::make_unique<char[]>(m_buffer_size);
			m_reader = &http_response_streambuf::underflow_deflated;
		}
		else
		{
			m_reader = &http_response_streambuf::underflow_normal;
		}
	}

	http_response_streambuf::http_response_streambuf(http_response_streambuf && other) noexcept
		: ext::streambuf(std::move(other)),
		m_parser(std::move(other.m_parser)),
		m_source(std::exchange(other.m_source, nullptr)),
		m_reader(std::exchange(other.m_reader, nullptr)),
#ifdef EXT_ENABLE_CPPZLIB
		m_inflator(std::move(other.m_inflator)),
#endif
		m_buffer(std::move(other.m_buffer)),
		m_buffer_size(std::move(other.m_buffer_size))
	{

	}

	http_response_streambuf & http_response_streambuf::operator =(http_response_streambuf && other) noexcept
	{
		if (this != &other)
		{
			this->~http_response_streambuf();
			new (this) http_response_streambuf(std::move(other));
		}

		return *this;
	}

	http_response_streambuf::http_response_streambuf(std::istream & is)
		: m_source(&is)
	{
		init();
	}

	http_response_streambuf::http_response_streambuf(http_response_parser && parser, std::istream & is)
		: m_parser(std::move(parser)), m_source(&is)
	{
		init();
	}

	http_response_stream::http_response_stream(http_response_stream && other) noexcept
		: std::istream(std::move(other)),
		  m_streambuf(std::move(other.m_streambuf))
	{
		set_rdbuf(&m_streambuf);
	}

	http_response_stream & http_response_stream::operator =(http_response_stream && other) noexcept
	{
		if (this != &other)
		{
			this->std::istream::operator= (std::move(other));
			m_streambuf = std::move(other.m_streambuf);
			set_rdbuf(&m_streambuf);
		}

		return *this;
	}
}}
