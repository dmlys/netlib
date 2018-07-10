#pragma once
#include <string>
#include <algorithm>
#include <ext/range.hpp>
#include <ext/type_traits.hpp>
#include <ext/iostreams/utility.hpp>

#include <ext/netlib/mime/encode_quoted_utils.hpp>
#include <ext/netlib/mime/encoding_tables.hpp>

namespace ext::netlib::mime
{
	template <class Iterator, class OutIterator>
	inline std::enable_if_t<ext::is_iterator_v<OutIterator>, OutIterator>
	encode_url(Iterator first, Iterator last, OutIterator out)
	{
		using namespace encoding_tables;
		return encode_utils::encode_quoted(percent_char, percent_encoding_array, first, last, out);
	}

	template <class Iterator, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	encode_url(Iterator first, Iterator last, OutputContainer & out)
	{
		encode_url(first, last, std::back_inserter(out));
	}

	template <class InputRange, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	encode_url(const InputRange & input, OutputContainer & out)
	{
		auto inplit = ext::as_literal(input);
		return encode_url(boost::begin(inplit), boost::end(inplit), out);
	}

	template <class OutputContainer = std::string, class InputRange>
	inline OutputContainer encode_url(const InputRange & input)
	{
		OutputContainer result;
		encode_url(input, result);
		return result;
	}

	template <class RandomAccessIterator, class Sink>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	encode_url(RandomAccessIterator first, RandomAccessIterator last, Sink & sink)
	{
		// encoding produce up to 3 times more than input
		constexpr auto buffer_size = encode_utils::tmp_buffer_size;
		constexpr auto step_size = buffer_size / 3;
		char buffer[buffer_size];

		while (first < last)
		{
			auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
			auto buf_end = encode_url(first, step_last, buffer);
			ext::iostreams::write_all(sink, buffer, buf_end - buffer);
			first = step_last;
		}

		return sink;
	}

	template <class InputRange, class Sink>
	inline std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	encode_url(const InputRange & input, Sink & out)
	{
		auto inplit = ext::as_literal(input);
		return encode_url(boost::begin(inplit), boost::end(inplit), out);
	}



	template <class Iterator, class OutIterator>
	inline std::enable_if_t<ext::is_iterator_v<OutIterator>, OutIterator>
	decode_url(Iterator first, Iterator last, OutIterator out)
	{
		using namespace encoding_tables;
		return encode_utils::decode_quoted(percent_char, first, last, out);
	}

	template <class Iterator, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	decode_url(Iterator first, Iterator last, OutputContainer & out)
	{
		decode_url(first, last, std::back_inserter(out));
	}

	template <class InputRange, class OutputContainer>
	inline std::enable_if_t<ext::is_container_v<OutputContainer>>
	decode_url(const InputRange & input, OutputContainer & out)
	{
		auto inplit = ext::as_literal(input);
		return decode_url(boost::begin(inplit), boost::end(inplit), out);
	}

	template <class OutputContainer = std::string, class InputRange>
	inline OutputContainer decode_url(const InputRange & input)
	{
		OutputContainer result;
		decode_url(input, result);
		return result;
	}

	template <class RandomAccessIterator, class Sink>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	decode_url(RandomAccessIterator first, RandomAccessIterator last, Sink & sink)
	{
		// decoding never produces more than input
		constexpr auto buffer_size = encode_utils::tmp_buffer_size;
		constexpr auto step_size = buffer_size;
		char buffer[buffer_size];

		while (first < last)
		{
			auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
			auto buf_end = decode_url(first, step_last, buffer);
			ext::iostreams::write_all(sink, buffer, buf_end - buffer);
			first = step_last;
		}

		return sink;
	}

	template <class InputRange, class Sink>
	inline std::enable_if_t<ext::iostreams::is_device_v<Sink>, Sink &>
	decode_url(const InputRange & input, Sink & out)
	{
		auto inplit = ext::as_literal(input);
		return decode_url(boost::begin(inplit), boost::end(inplit), out);
	}
}

namespace ext::netlib
{
	using mime::encode_url;
	using mime::decode_url;
}
