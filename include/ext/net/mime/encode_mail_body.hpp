#pragma once
#include <ext/is_string.hpp>
#include <ext/type_traits.hpp> // for is_iterator
#include <ext/base64.hpp>

#include <ext/net/mime/encoding_tables.hpp>
#include <ext/net/mime/encode_quoted_utils.hpp>
#include <ext/net/mime/mail_encoding.hpp>
#include <ext/net/smtp/smtp_extensions.hpp>

namespace ext::net::mime
{
	/// Checks if given text [first;last) is suitable for 7bit encoding.
	/// Text is searched for crln -> lines are found.
	/// Each line should not longer then max_size and chars should be in [32;128) range
	template <class RandomAccessIterator>
	bool check_7bit_valid(RandomAccessIterator first, RandomAccessIterator last, std::size_t max_size = MailDefaultLineSize)
	{
		using namespace encoding_tables;
		const auto is_valid_char = [](auto ch) { return ch == ' ' or ch == '\t' or (ch >= 32 and ch < 128); };

		for (;;)
		{
			auto it = std::search(first, last, linebreak, linebreak + linebreak_size);
			auto length = it - first + linebreak_size;

			if (length > max_size) return false;
			if (not std::all_of(first, it, is_valid_char)) return false;

			if (it == last) break;
			first = it + linebreak_size;
		}

		return true;
	}

	/// Checks if given text [first;last) is suitable for 8bit encoding.
	/// Text is searched for crln -> lines are found.
	/// Each line should not longer then max_size, chars can be any
	template <class RandomAccessIterator>
	bool check_8bit_valid(RandomAccessIterator first, RandomAccessIterator last, std::size_t max_size = MailMaxLineSize)
	{
		using namespace encoding_tables;
		
		for (;;)
		{
			auto it = std::search(first, last, linebreak, linebreak + linebreak_size);
			auto length = it - first + linebreak_size;
			if (length > max_size) return false;

			if (it == last) break;
			first = it + linebreak_size;
		}

		return true;
	}

	/// Calculates suitable body encoding based on text and allowed SMTP extensions
	template <class RandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>, mail_encoding>
	estimate_body_encoding(RandomAccessIterator first, RandomAccessIterator last, smtp_extensions_bitset extensions)
	{
		constexpr std::ptrdiff_t huge_size = 1024 * 1024;

		if (last - first > huge_size)
		{
			if (extensions[smtp_extensions::binary_mime])
				return mail_encoding::binary;
		}
		else
		{
			if (check_7bit_valid(first, last))
				return mail_encoding::bit7;

			if (extensions[smtp_extensions::bit8_mime] and check_8bit_valid(first, last))
				return mail_encoding::bit8;
		}

		using namespace encoding_tables;
		using namespace encode_utils;

		std::size_t count = last - first;
		std::size_t qenc_est = 0;
		for (;;)
		{
			auto it = std::search(first, last, linebreak, linebreak + linebreak_size);
			qenc_est += encode_utils::estimate_count(quoted_printable_array, first, it);

			if (it == last) break;
			first = it + linebreak_size;
		}

		auto quoted_groups_count = (qenc_est - count) / 2;
		return count / quoted_groups_count >= 3 ? mail_encoding::quoted_printable : mail_encoding::base64;
	}

	/// Calculates suitable body encoding based on text and allowed SMTP extensions
	template <class String>
	std::enable_if_t<ext::is_string_v<String>, mail_encoding>
	estimate_body_encoding(const String & str, smtp_extensions_bitset extensions)
	{
		auto lit = ext::str_view(str);
		return estimate_body_encoding(lit.begin(), lit.end(), extensions);
	}


	/// Encodes email body text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME Internet Message Body RFC 2045.
	/// Only utf-8 is supported, internally some utf-8 processing is done.
	/// https://tools.ietf.org/html/rfc2045
	///
	/// Formating and encoding is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n
	///  * text is base64 encoded
	///  * splitting is done on base64 group boundaries, i.e. num of base64 chars is multiple of 4
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class RandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>, std::size_t>
	encode_base64_mail_body(Destination & dest, std::size_t cur_pos, std::size_t line_size, RandomAccessIterator first, RandomAccessIterator last)
	{
		constexpr std::size_t buffer_size = tmp_buffer_size;
		constexpr std::size_t step_size = ext::base64::decode_estimation(buffer_size);
		char buffer[buffer_size];

		if (first == last) return cur_pos;
		if (line_size <= MailMinLineSize) throw std::invalid_argument("encode_base64_mail_body: line_size to small");

		line_size = std::min(line_size, MailMaxLineSize);
		line_size -= 2;

		if (cur_pos >= line_size)
		{
			write_string(dest, "\r\n");
			cur_pos = 0;
		}

		while (first < last)
		{
			auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
			auto stopped = ext::encode_base64(first, step_last, buffer);
			auto start = buffer;

			// stopped > start always
			while (static_cast<std::size_t>(stopped - start) > line_size - cur_pos)
			{
				auto written = line_size - cur_pos;
				write_string(dest, start, written);
				start += written;

				write_string(dest, "\r\n");
				cur_pos = 0;
			}

			write_string(dest, start, stopped);
			cur_pos += stopped - start;

			first = step_last;
		}

		return cur_pos;
	}


	/// Encodes email body text into destination(sink, iterator or STL container)
	/// according to MIME Internet Message Body RFC 2045.
	/// Only utf-8 is supported, internally some utf-8 processing is done.
	/// https://tools.ietf.org/html/rfc2045
	///
	/// Formating and encoding is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n
	///  * text is base64 encoded
	///  * splitting is done on base64 group boundaries, i.e. num of base64 chars is multiple of 4
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class BodyString>
	inline std::enable_if_t<ext::is_string_v<BodyString>, std::size_t>
	encode_base64_mail_body(Destination & dest, std::size_t cur_pos, std::size_t line_size, const BodyString & body)
	{
		auto lit = ext::str_view(body);
		return encode_base64_mail_body(dest, cur_pos, line_size, lit.begin(), lit.end());
	}

	
	/// Encodes email body text [first;last) into destination(sink, iterator or STL container)
	/// according to MIME Internet Message Body RFC 2045.
	/// https://tools.ietf.org/html/rfc2045
	/// https://en.wikipedia.org/wiki/Quoted-printable
	///
	/// Formating and encoding is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n
	///  * text is quoted printable encoded
	///  * if natural crln is found - it will be printed as is(hard line break)
	///  * if line length exceeded - soft line break(=\r\n) will be inserted and new line started
	///  * space characters(' ', '\t') are represented as is, except if at the end of encoded line,
	///    in this case they are protected via encoding or soft line break
	///  * splitting is done on group boundaries, i.e. '=20' will not be split in any way (=/20, =2/0)
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class RandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<RandomAccessIterator>, std::size_t>
	encode_quoted_printable_mail_body(Destination & dest, std::size_t cur_pos, std::size_t line_size, RandomAccessIterator first, RandomAccessIterator last)
	{
		using namespace encode_utils;
		using namespace encoding_tables;

		constexpr std::size_t buffer_size = tmp_buffer_size;
		constexpr std::size_t step_size = buffer_size / 3;
		char buffer[buffer_size];

		if (first == last) return cur_pos;
		if (line_size <= MailMinLineSize) throw std::invalid_argument("encode_quoted_printable_mail_body: line_size to small");

		line_size = std::min(line_size, MailMaxLineSize);
		line_size -= 1; // 1 - for soft line break "=\r\n"

		const auto escaped_crln = ext::str_view("=0D=0A");
		const auto soft_line_break = ext::str_view("=\r\n");
		const auto hard_line_break = ext::str_view("\r\n");
		const auto is_space = [](char ch) { return ch == ' ' or ch == '\t'; };

		RandomAccessIterator stopped, stop;
		char * out_first, * out_last;
		std::size_t step_count, written;

		do {
			step_count = std::min<std::size_t>(step_size, last - first);
			stop = first + step_count;

			std::tie(stopped, std::ignore, written) =
				encode_quoted_bounded(quoted_printable_char, quoted_printable_array, line_size - cur_pos, first, stop, buffer);
			
			out_first = buffer;
			out_last  = buffer + written;

			// if there are natural line breaks(crln) we must print them as is,
			// also if there are space(' ', '\t') before that line break, it must be protected by quoted encoding
			for (;;)
			{
				auto it = std::search(out_first, out_last, escaped_crln.begin(), escaped_crln.end());
				if (out_last == it) break; // not found escaped_crln
				
				auto out_until = it;
				if (out_first != it and is_space(*std::prev(it)))
				{
					// escaped_crln not at start and we have trailing ascii space character: ' ', '\t'
					// need to quote because of following hard line break
					out_until = std::prev(it);
					out_until = quote_char(quoted_printable_char, *out_until, out_until);
				}

				write_string(dest, out_first, out_until);
				write_string(dest, hard_line_break);
				out_first = it + escaped_crln.size();
				cur_pos = 0, written = out_last - out_first;
			}
			
			write_string(dest, out_first, out_last);
			first = stopped, cur_pos += written;

			if (cur_pos == line_size) // encode_quoted_bounded stopped by max_output
			{
				// insert soft line break
				write_string(dest, soft_line_break);
				cur_pos = 0;
			}

			// until we we have more to write and wrote all at this iteration
		} while (first < last);

		// if ascii space character ' ', '\t at the end of whole body - protect it with soft line break
		if (out_first != out_last and is_space(*(out_last - 1)))
		{
			write_string(dest, soft_line_break);
			cur_pos = 0;
		}

		return cur_pos;
	}

	/// Encodes email body text into destination(sink, iterator or STL container)
	/// according to MIME Internet Message Body RFC 2045.
	/// https://tools.ietf.org/html/rfc2045
	/// https://en.wikipedia.org/wiki/Quoted-printable
	///
	/// Formating and encoding is done in following way:
	///  * line length does not exceed line_size chars(including \r\n).
	///    lines do end with \r\n
	///  * text is quoted printable encoded
	///  * if natural crln is found - it will be printed as is(hard line break)
	///  * if line length exceeded - soft line break(=\r\n) will be inserted and new line started
	///  * space characters(' ', '\t') are represented as is, except if at the end of encoded line,
	///    in this case they are protected via encoding or soft line break
	///  * splitting is done on group boundaries, i.e. '=20' will not be split in any way (=/20, =2/0)
	///  * splitting is done only between full utf-8 sequences, that way every word is a valid utf-8
	template <class Destination, class BodyString>
	inline std::enable_if_t<ext::is_string_v<BodyString>, std::size_t>
	encode_quoted_printable_mail_body(Destination & dest, std::size_t cur_pos, std::size_t line_size, const BodyString & body)
	{
		auto lit = ext::str_view(body);
		return encode_quoted_printable_mail_body(dest, cur_pos, line_size, lit.begin(), lit.end());
	}

	/// Encodes email body text into destination(sink, iterator or STL container) according to given encoding
	template <class Destination, class BodyString>
	std::enable_if_t<ext::is_string_v<BodyString>, std::size_t>
	encode_mail_body(Destination & dest, mail_encoding enc, const BodyString & body)
	{
		switch (enc)
		{
			default:
			case bit7:
			case bit8:
			case binary:
				return write_string(dest, body);

			case quoted_printable:
				return encode_quoted_printable_mail_body(dest, 0, MailQPDefaultLineSzie, body);

			case base64:
				return encode_base64_mail_body(dest, 0, MailDefaultLineSize, body);
		}
	}
}
