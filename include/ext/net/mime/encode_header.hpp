#pragma once
#include <ext/net/mime/encode_quoted_utils.hpp>
#include <ext/net/mime/encoding_tables.hpp>
#include <ext/net/mime/bencode_header.hpp>
#include <ext/net/mime/qencode_header.hpp>

namespace ext::net::mime
{
	template <class Destination, class RandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>, std::size_t>
	encode_header_folded(Destination & dest, std::size_t cur_pos, std::size_t line_size,
	                     RandomAccessIterator first, RandomAccessIterator last)
	{
		using namespace encode_utils;
		using namespace encoding_tables;
		using namespace ext::base64;

		std::size_t count = last - first;
		std::size_t qenc_est = estimate_count(qencoding_array, first, last);		

		// simple case, without any encoding
		if (qenc_est == count and count <= line_size - linebreak_size)
		{
			for (;;)
			{
				auto write_count = std::min<std::size_t>(line_size - linebreak_size - cur_pos, count);
				write_string(dest, first, first + write_count);
				count -= write_count;
				first += write_count;
				cur_pos += write_count;
				
				if (not count) break;

				write_string(dest, linebreak, linebreak_size);
				cur_pos = linebreak_prefix_size;
			};

			return cur_pos;
		}
		else
		{
			auto quoted_groups_count = (qenc_est - count) / 2;
			return count / quoted_groups_count >= 3
				? qencode_header_folded(dest, cur_pos, line_size, first, last)
				: bencode_header_folded(dest, cur_pos, line_size, first, last);
		}

	}

	template <class Destination, class ValueString>
	inline std::enable_if_t<ext::is_string_v<ValueString>, std::size_t>
	encode_header_folded(Destination & dest, std::size_t cur_pos, std::size_t line_size, const ValueString & value)
	{
		auto inplit = ext::str_view(value);
		return encode_header_folded(dest, cur_pos, line_size, inplit.begin(), inplit.end());
	}

	template <class Destination, class NameString, class ValueString>
	std::enable_if_t<ext::is_string_v<NameString> and ext::is_string_v<ValueString>, std::size_t>
	encode_header_folded(Destination & dest, std::size_t line_size, const NameString & name, const ValueString & value)
	{
		auto namelit = ext::str_view(name);
		auto vallit  = ext::str_view(value);
		auto namewidth = namelit.size();

		write_string(dest, namelit);
		write_string(dest, ": ");

		return encode_header_folded(dest, namewidth + 2, line_size, vallit);
	}
}
