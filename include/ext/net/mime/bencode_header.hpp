#pragma once
#include <ext/base64.hpp>
#include <ext/is_string.hpp>
#include <ext/type_traits.hpp> // for is_iterator
#include <ext/net/write_string.hpp>
#include <ext/net/mime/encode_quoted_utils.hpp>
#include <ext/net/mime/encoding_tables.hpp>

namespace ext::net::mime
{
	/// Encodes text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// This function does not splits/folds anything, see bencode_header_folded.
	/// Formating and encoding is done in following way:
	///  * "word" starts with =?utf-8?b? and ends with ?=
	///  * "word" contents are base64 encoded
	template <class Destination, class RandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>>
	bencode_header(Destination & dest, RandomAccessIterator first, RandomAccessIterator last)
	{
		using namespace encoding_tables;

		if (first == last) return;
		
		write_string(dest, bencoded_prefix, bencoded_prefix_size);

		if constexpr (ext::is_iterator_v<Destination>)
			dest = encode_base64(first, last, dest);
		else
			encode_base64(first, last, dest);

		write_string(dest, encoded_suffix, encoded_suffix_size);
	}

	/// Encodes header name and header value into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// This function does not splits/folds anything, see bencode_header_folded.
	/// Header name is written as is, formating and encoding of value is done in following way:
	///  * "word" starts with =?utf-8?b? and ends with ?=
	///  * "word" contents are base64 encoded
	template <class Destination, class NameString, class ValueString>
	std::enable_if_t<ext::is_string_v<NameString> and ext::is_string_v<ValueString>>
	bencode_header(Destination & dest, const NameString & name, const ValueString & value)
	{
		write_string(dest, name);
		write_string(dest, ": ");

		auto lit = ext::str_view(value);
		bencode_header(dest, boost::begin(value), boost::end(value));
	}


	/// Encodes text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// Only utf-8 is supported, internally some utf-8 processing is done.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// Formating and encoding is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n, new ones automatically start with space
	///  * each "word" starts with =?utf-8?b? and ends with ?= (all symbols are accounted by line_size)
	///  * "word" contents are base64 encoded
	///  * splitting is done on base64 group boundaries, i.e. num of base64 chars is multiple of 4
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class RandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>, std::size_t>
	bencode_header_folded(Destination & dest, std::size_t cur_pos, std::size_t line_size,
	                      RandomAccessIterator first, RandomAccessIterator last)
	{
		using namespace ext::base64;
		using namespace encoding_tables;
		using namespace encode_utils;

		if (first == last) return cur_pos;
		if (line_size <= MailMinLineSize) throw std::invalid_argument("bencode_header: line_size to small");
		
		line_size = std::min(line_size, MailMaxLineSize);
		line_size -= linebreak_size;
		
		// can we write at least 1 base64 group on this line
		if (cur_pos + bencoded_prefix_size + encoded_suffix_size + OutputGroupSize >= line_size)
		{
			write_string(dest, linebreak, linebreak_size + linebreak_prefix_size);
			cur_pos = linebreak_prefix_size;
		}
		
		write_string(dest, bencoded_prefix, bencoded_prefix_size);
		cur_pos += bencoded_prefix_size;
		
		std::size_t count = last - first;
		for (;;)
		{
			std::size_t read_count = (line_size - encoded_suffix_size - cur_pos) / OutputGroupSize * InputGroupSize;
			read_count = utf8_trunc_count(count, read_count, first);
			auto written = ext::base64::encode_estimation(read_count);

			if constexpr (ext::is_iterator_v<Destination>)
				dest = ext::encode_base64(first, first + read_count, dest);
			else
				ext::encode_base64(first, first + read_count, dest);
			
			cur_pos += written;
			first += read_count;
			count -= read_count;
		
			if (count == 0)
				break;
		
			write_string(dest, encoded_suffix, encoded_suffix_size);
			write_string(dest, linebreak, linebreak_size + linebreak_prefix_size);
			write_string(dest, bencoded_prefix, bencoded_prefix_size);
			cur_pos = linebreak_prefix_size + bencoded_prefix_size;
		}
		
		write_string(dest, encoded_suffix, encoded_suffix_size);
		return cur_pos + encoded_suffix_size;
	}
		
	/// Encodes text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// Only utf-8 is supported, internally some utf-8 processing is done.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// Formating and encoding is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n, new ones automatically start with space
	///  * each "word" starts with =?utf-8?b? and ends with ?= (all symbols are accounted by line_size)
	///  * "word" contents are base64 encoded
	///  * splitting is done on base64 group boundaries, i.e. num of base64 chars is multiple of 4
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class ValueString>
	inline std::enable_if_t<ext::is_string_v<ValueString>, std::size_t>
	bencode_header_folded(Destination & dest, std::size_t cur_pos, std::size_t line_size, const ValueString & value)
	{
		auto inplit = ext::str_view(value);
		return bencode_header_folded(dest, cur_pos, line_size, boost::begin(inplit), boost::end(inplit));
	}

	/// Encodes text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// Only utf-8 is supported, internally some utf-8 processing is done.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// Header name is written as is, formating and encoding of value is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n, new ones automatically start with space
	///  * each "word" starts with =?utf-8?b? and ends with ?= (all symbols are accounted by line_size)
	///  * "word" contents are base64 encoded
	///  * splitting is done on base64 group boundaries, i.e. num of base64 chars is multiple of 4
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class NameString, class ValueString>
	std::enable_if_t<ext::is_string_v<NameString> and ext::is_string_v<ValueString>, std::size_t>
	bencode_header_folded(Destination & dest, std::size_t line_size, const NameString & name, const ValueString & value)
	{
		auto namelit = ext::str_view(name);
		auto vallit = ext::str_view(value);
		auto namewidth = boost::size(namelit);

		write_string(dest, namelit);
		write_string(dest, ": ");

		return bencode_header_folded(dest, namewidth + 2, line_size, vallit);
	}
} // namespace ext::net::mime
