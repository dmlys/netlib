#pragma once
#include <ext/is_string.hpp>
#include <ext/type_traits.hpp> // for is_iterator
#include <ext/netlib/mime/encode_quoted_utils.hpp>
#include <ext/netlib/mime/encoding_tables.hpp>

namespace ext::netlib::mime
{
	/// Encodes text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// This function does not splits/folds anything, see bencode_header_folded.
	/// Formating and encoding is done in following way:
	///  * "word" starts with =?utf-8?q? and ends with ?=
	///  * "word" contents are base64 encoded
	template <class Destination, class RandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>>
	qencode_header(Destination & dest, RandomAccessIterator first, RandomAccessIterator last)
	{
		using namespace encode_utils;
		using namespace encoding_tables;

		if (first == last) return;
		
		write_string(dest, qencoded_prefix, qencoded_prefix_size);
		quote(dest, qencoding_char, qencoding_array, first, last);
		write_string(dest, encoded_suffix, encoded_suffix_size);
	}

	/// Encodes header name and header value into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// This function does not splits/folds anything, see bencode_header_folded.
	/// Header name is written as is, formating and encoding of value is done in following way:
	///  * "word" starts with =?utf-8?q? and ends with ?=
	///  * "word" contents are base64 encoded
	template <class Destination, class NameString, class ValueString>
	std::enable_if_t<ext::is_string_v<NameString> and ext::is_string_v<ValueString>>
	qencode_header(Destination & dest, const NameString & name, const ValueString & value)
	{
		write_string(dest, name);
		write_string(dest, ": ");

		auto lit = ext::as_literal(value);
		qencode_header(dest, boost::begin(lit), boost::end(lit));
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
	///  * each "word" starts with =?utf-8?q? and ends with ?= (all symbols are accounted by line_size)
	///  * "word" contents are q-encoded
	///  * splitting is done on group boundaries, i.e. '=20' will not be split in any way (=/20, =2/0)
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class RandomAccessIterator, class Destination>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>, std::size_t>
	qencode_header_folded(Destination & dest, std::size_t cur_pos, std::size_t line_size,
	                      RandomAccessIterator first, RandomAccessIterator last)
	{
		using namespace encode_utils;
		using namespace encoding_tables;

		if (first == last) return cur_pos;
		if (line_size <= MailMinLineSize) throw std::invalid_argument("qencode_header_folded: line_size to small");
			
		line_size = std::min(line_size, MailMaxLineSize);
		line_size -= linebreak_size;

		// can we write at least 1 qencoded symbol on this line
		if (cur_pos + qencoded_prefix_size + encoded_suffix_size + 3 >= line_size)
		{
			write_string(dest, linebreak, linebreak_size + linebreak_prefix_size);
			cur_pos = linebreak_prefix_size;
		}

		write_string(dest, qencoded_prefix, qencoded_prefix_size);
		cur_pos += qencoded_prefix_size;
			
		for (;;)
		{
			std::size_t write_count = line_size - encoded_suffix_size - cur_pos;
			auto read_count = utf8_trunc_count(last - first, write_count, first);
			
			std::tie(first, write_count) =
				quote_bounded(dest, write_count, qencoding_char, qencoding_array, first, first + read_count);

			cur_pos += write_count;
			
			if (first == last)
				break;

			write_string(dest, encoded_suffix, encoded_suffix_size);
			write_string(dest, linebreak, linebreak_size + linebreak_prefix_size);
			write_string(dest, qencoded_prefix, qencoded_prefix_size);
			cur_pos = linebreak_prefix_size + qencoded_prefix_size;
		};

		write_string(dest, encoded_suffix);
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
	///  * each "word" starts with =?utf-8?q? and ends with ?= (all symbols are accounted by line_size)
	///  * "word" contents are q-encoded
	///  * splitting is done on group boundaries, i.e. '=20' will not be split in any way (=/20, =2/0)
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class ValueString>
	std::enable_if_t<ext::is_string_v<ValueString>, std::size_t>
	qencode_header_folded(Destination & dest, std::size_t cur_pos, std::size_t line_size, const ValueString & val)
	{
		auto inplit = ext::as_literal(val);
		return qencode_header_folded(dest, cur_pos, line_size, boost::begin(inplit), boost::end(inplit));
	}

	/// Encodes text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME encoded-word RFC 2047.
	/// Only utf-8 is supported, internally some utf-8 processing is done.
	/// https://tools.ietf.org/html/rfc2047
	/// https://en.wikipedia.org/wiki/MIME#Encoded-Word
	///
	/// Name is written as is, formating and encoding of value is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n, new ones automatically start with space
	///  * each "word" starts with =?utf-8?q? and ends with ?= (all symbols are accounted by line_size)
	///  * "word" contents are q-encoded
	///  * splitting is done on group boundaries, i.e. '=20' will not be split in any way (=/20, =2/0)
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class NameString, class ValueString>
	std::enable_if_t<ext::is_string_v<NameString> and ext::is_string_v<ValueString>, std::size_t>
	qencode_header_folded(Destination & dest, std::size_t line_size, const NameString & name, const ValueString & value)
	{
		auto namelit = ext::as_literal(name);
		auto vallit = ext::as_literal(value);
		auto namewidth = boost::size(namelit);

		write_string(dest, namelit);
		write_string(dest, ": ");

		return qencode_header_folded(dest, namewidth + 2, line_size, vallit);
	}

} // namespace ext::netlib::mime
