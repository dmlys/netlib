#pragma once
#include <string>
#include <ext/is_iterator.hpp>
#include <ext/range.hpp>

#include <ext/iostreams/write.hpp>
#include <ext/netlib/codecs/encode_quoted_utils.hpp>
#include <ext/netlib/codecs/encoding_tables.hpp>

namespace ext {
namespace netlib
{
	template <class Iterator, class OutIterator>
	inline std::enable_if_t<ext::is_iterator<OutIterator>::value, OutIterator>
	encode_url(Iterator first, Iterator last, OutIterator out)
	{
		using namespace encoding_tables;
		return encode_utils::encode_quoted(percent_char, percent_encoding_array, first, last, out);
	}

	template <class InputRange, class OutputContainer>
	inline std::enable_if_t<ext::is_range<OutputContainer>::value>
	encode_url(const InputRange & input, OutputContainer & out)
	{
		auto inplit = ext::as_literal(input);
		encode_url(boost::begin(inplit), boost::end(inplit), std::back_inserter(out));
	}

	template <class OutputContainer = std::string, class InputRange>
	inline OutputContainer encode_url(const InputRange & input)
	{
		OutputContainer result;
		encode_url(input, result);
		return result;
	}

	template <class RandomAccessIterator, class Sink>
	std::enable_if_t<not ext::is_iterator<Sink>::value>
	encode_url(RandomAccessIterator first, RandomAccessIterator last, Sink & sink)
	{
		// encoding produce up to 3 times more than input
		constexpr unsigned buffer_size = 256;
		constexpr unsigned step_size = buffer_size / 3;
		char buffer[buffer_size];

		while (first < last)
		{
			auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
			auto buf_end = encode_url(first, step_last, buffer);
			ext::iostreams::write_all(sink, buffer, buf_end - buffer);
			first = step_last;
		}
	}

	template <class InputRange, class Sink>
	inline std::enable_if_t<not ext::is_range<Sink>::value>
	encode_url(const InputRange & input, Sink & out)
	{
		auto inplit = ext::as_literal(input);
		encode_url(boost::begin(inplit), boost::end(inplit), out);
	}



	template <class Iterator, class OutIterator>
	inline std::enable_if_t<ext::is_iterator<OutIterator>::value, OutIterator>
	decode_url(Iterator first, Iterator last, OutIterator out)
	{
		using namespace encoding_tables;
		return encode_utils::decode_quoted(percent_char, first, last, out);
	}

	template <class InputRange, class OutputContainer>
	inline std::enable_if_t<ext::is_range<OutputContainer>::value>
	decode_url(const InputRange & input, OutputContainer & out)
	{
		auto inplit = ext::as_literal(input);
		decode_url(boost::begin(inplit), boost::end(inplit), std::back_inserter(out));
	}

	template <class OutputContainer = std::string, class InputRange>
	inline OutputContainer decode_url(const InputRange & input)
	{
		OutputContainer result;
		decode_url(input, result);
		return result;
	}

	template <class RandomAccessIterator, class Sink>
	std::enable_if_t<not ext::is_iterator<Sink>::value>
	decode_url(RandomAccessIterator first, RandomAccessIterator last, Sink & sink)
	{
		// decoding never produces more than input
		constexpr unsigned buffer_size = 256;
		constexpr unsigned step_size = buffer_size;
		char buffer[buffer_size];

		while (first < last)
		{
			auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
			auto buf_end = decode_url(first, step_last, buffer);
			ext::iostreams::write_all(sink, buffer, buf_end - buffer);
			first = step_last;
		}
	}

	template <class InputRange, class Sink>
	inline std::enable_if_t<not ext::is_range<Sink>::value>
	decode_url(const InputRange & input, Sink & out)
	{
		auto inplit = ext::as_literal(input);
		decode_url(boost::begin(inplit), boost::end(inplit), out);
	}
}}
