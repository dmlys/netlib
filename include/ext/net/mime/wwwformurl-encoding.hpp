#pragma once
#include <string>
#include <algorithm>
#include <ext/range.hpp>
#include <ext/type_traits.hpp>
#include <ext/iostreams/utility.hpp>

#include <ext/net/mime/encode_quoted_utils.hpp>
#include <ext/net/mime/encoding_tables.hpp>

// Encode and decode functions for application/x-www-form-urlencoded encoding.
// This is similar to URL encoding, except space is encoded as '+'


namespace ext::net::mime
{
	template <class Iterator, class OutIterator>
	inline std::enable_if_t<ext::is_iterator_v<OutIterator>, OutIterator>
	encode_wwwformurl(Iterator first, Iterator last, OutIterator out)
	{
		using namespace encoding_tables;
		return encode_utils::encode_quoted(percent_char, wwwformurl_encoding_array, first, last, out);
	}

	template <class Iterator, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	encode_wwwformurl(Iterator first, Iterator last, OutputContainer & out)
	{
		encode_wwwformurl(first, last, std::back_inserter(out));
	}

	template <class InputRange, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	encode_wwwformurl(const InputRange & input, OutputContainer & out)
	{
		auto inplit = ext::str_view(input);
		return encode_wwwformurl(boost::begin(inplit), boost::end(inplit), out);
	}

	template <class OutputContainer = std::string, class InputRange>
	inline OutputContainer encode_wwwformurl(const InputRange & input)
	{
		OutputContainer result;
		encode_wwwformurl(input, result);
		return result;
	}

	template <class RandomAccessIterator, class Sink>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	encode_wwwformurl(RandomAccessIterator first, RandomAccessIterator last, Sink & sink)
	{
		// encoding produce up to 3 times more than input
		constexpr auto buffer_size = encode_utils::tmp_buffer_size;
		constexpr auto step_size = buffer_size / 3;
		char buffer[buffer_size];

		while (first < last)
		{
			auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
			auto buf_end = encode_wwwformurl(first, step_last, buffer);
			ext::iostreams::write_all(sink, buffer, buf_end - buffer);
			first = step_last;
		}

		return sink;
	}

	template <class InputRange, class Sink>
	inline std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	encode_wwwformurl(const InputRange & input, Sink & out)
	{
		auto inplit = ext::str_view(input);
		return encode_wwwformurl(boost::begin(inplit), boost::end(inplit), out);
	}



	template <class Iterator, class OutIterator>
	inline std::enable_if_t<ext::is_iterator_v<OutIterator>, OutIterator>
	decode_wwwformurl(Iterator first, Iterator last, OutIterator out)
	{
		using namespace encoding_tables;
		return encode_utils::decode_quoted(percent_char, wwwformurl_decoding_array, first, last, out);
	}

	template <class Iterator, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	decode_wwwformurl(Iterator first, Iterator last, OutputContainer & out)
	{
		decode_wwwformurl(first, last, std::back_inserter(out));
	}

	template <class InputRange, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	decode_wwwformurl(const InputRange & input, OutputContainer & out)
	{
		auto inplit = ext::str_view(input);
		return decode_wwwformurl(boost::begin(inplit), boost::end(inplit), out);
	}

	template <class OutputContainer = std::string, class InputRange>
	inline OutputContainer decode_wwwformurl(const InputRange & input)
	{
		OutputContainer result;
		decode_wwwformurl(input, result);
		return result;
	}

	template <class RandomAccessIterator, class Sink>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	decode_wwwformurl(RandomAccessIterator first, RandomAccessIterator last, Sink & sink)
	{
		// decoding never produces more than input
		constexpr auto buffer_size = encode_utils::tmp_buffer_size;
		constexpr auto step_size = buffer_size;
		char buffer[buffer_size];

		while (first < last)
		{
			auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
			auto buf_end = decode_wwwformurl(first, step_last, buffer);
			ext::iostreams::write_all(sink, buffer, buf_end - buffer);
			first = step_last;
		}

		return sink;
	}

	template <class InputRange, class Sink>
	inline std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	decode_wwwformurl(const InputRange & input, Sink & out)
	{
		auto inplit = ext::str_view(input);
		return decode_wwwformurl(boost::begin(inplit), boost::end(inplit), out);
	}
}

namespace ext::net
{
	using mime::encode_wwwformurl;
	using mime::decode_wwwformurl;
}
