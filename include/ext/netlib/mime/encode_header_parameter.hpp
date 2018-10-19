#pragma once
#include <algorithm>
#include <ext/itoa.hpp>
#include <ext/type_traits.hpp>
#include <ext/range/range_traits.hpp>
#include <ext/range/as_literal.hpp>

#include <ext/netlib/mime/encode_quoted_utils.hpp>
#include <ext/netlib/mime/encoding_tables.hpp>

namespace ext::netlib::mime
{
	namespace detail
	{
		/************************************************************************/
		/*          encode_header_parameter_folded implementation methods       */
		/************************************************************************/
		/// Formats and writes prefix =*<num>*"  into dest, returns prefix length
		template <class Destination>
		std::size_t write_parameter_num_prefix(Destination & dest, unsigned num)
		{
			char buffer[std::numeric_limits<unsigned>::digits10 + 3];
			auto last = buffer + sizeof(buffer) - 1;
			auto first = ext::unsafe_itoa(num, buffer, last - buffer, 10);

			*--first = '*';
			*--last  = '*';
			*++last  = '=';

			std::size_t count = last - first + 1;
			write_string(dest, first, count);
			return count;
		}

		/// Writes parameter with name [name_first; name_last) and value [val_first; val_last) into dest, without encoding,
		/// quoted - quote or not parameter value(wrapping in "")
		/// cur_pos - current position in current line, returns new position after write
		template <class Destination, class NameIterator, class ValIterator>
		std::size_t encode_simple_header_parameter(
			Destination & dest, bool quoted, std::size_t cur_pos, std::size_t line_size,
			NameIterator name_first, NameIterator name_last,
			ValIterator  val_first,  ValIterator  val_last)
		{
			using namespace encoding_tables;

			line_size = std::min(line_size, MailMaxLineSize);
			line_size -= linebreak_size;
				
			// this function is internal, and parameters are checked on calling side
			// name_size + val_size + '=' + optional quotes
			std::size_t count = (name_last - name_first) + (val_last - val_first) + 1 + (quoted ? 2 : 0);
			assert(count <= line_size);

			if (count + cur_pos > line_size)
			{
				write_string(dest, linebreak, linebreak_size + linebreak_prefix_size);
				cur_pos = linebreak_prefix_size;
			}

			write_string(dest, name_first, name_last);
			write_string(dest, "=");

			if (quoted) write_string(dest, "\"");
			write_string(dest, val_first, val_last);
			if (quoted) write_string(dest, "\"");

			return cur_pos + count;
		}

		/// Encodes parameter with name [name_first;name_last) and value [val_first;val_last) into dest,
		/// according to rfc 2231 splitting string where needed.
		/// Function guarantees to not break utf8 sequences.
		/// [val_first; val_last) must be valid utf-8 text.
		/// cur_pos - current position in current line, returns new position after write
		template <class Destination, class NameRandomAccessIterator, class ValRandomAccessIterator>
		std::size_t encode_folded_header_parameter(
			Destination & dest, std::size_t cur_pos, std::size_t line_size,
			NameRandomAccessIterator name_first, NameRandomAccessIterator name_last,
			ValRandomAccessIterator  val_first,  ValRandomAccessIterator  val_last)
		{
			using namespace encoding_tables;
			using namespace encode_utils;
			unsigned num = 0;

			line_size = std::min(line_size, MailMaxLineSize);
			line_size -= linebreak_size;

			constexpr unsigned num_prefix_size = 4; // *0*=
			constexpr std::size_t prefix_buffer_size = std::numeric_limits<unsigned>::digits10 + num_prefix_size - 1;
			const std::size_t name_size = name_last - name_first;

			const auto min_size = name_size + prefix_buffer_size + parameter_encoding_prefix_size + parameter_separator_size;
			const auto line_required = 10 + name_size + num_prefix_size + parameter_encoding_prefix_size + parameter_separator_size;

			EXT_UNUSED(min_size);

			if (cur_pos + line_required > line_size)
			{
				write_string(dest, linebreak, linebreak_size + linebreak_prefix_size);
				cur_pos = linebreak_prefix_size;
			}
				
			// write name
			write_string(dest, name_first, name_last);
			cur_pos += name_size;

			// write num prefix
			cur_pos += write_parameter_num_prefix(dest, num);
			// and char code scheme(utf-8'') this step is done only once for <parameter>*0* iteration
			write_string(dest, parameter_encoding_prefix, parameter_encoding_prefix_size);
			cur_pos += parameter_encoding_prefix_size;

			for (;;)
			{
				std::size_t write_count = line_size - parameter_separator_size - cur_pos;
				auto read_count = utf8_trunc_count(val_last - val_first, write_count, val_first);

				std::tie(val_first, write_count) =
					quote_bounded(dest, write_count, parameter_char, parameter_unqouted_array, val_first, val_first + read_count);

				cur_pos += write_count;

				if (val_first == val_last)
					break;

				write_string(dest, parameter_linebreak, parameter_linebreak_size);
				cur_pos = linebreak_prefix_size;

				// write name
				write_string(dest, name_first, name_last);
				cur_pos += name_size;

				cur_pos += write_parameter_num_prefix(dest, ++num);
			}

			return cur_pos;
		}

	} // namespace detail

	/// Encodes header parameter according to rfc 2231, MIME header parameter
	/// https://tools.ietf.org/html/rfc2231
	/// https://en.wikipedia.org/wiki/MIME#Content-Disposition
	/// * sink                    - there result would be written
	/// * cur_pos                 - current line position
	/// * line_size               - maximum line size
	/// * [name_first; name_last) - header name, must not be empty
	/// * [val_first; val_last)   - header value, must not be empty
	///
	/// returns new line position
	/// 
	/// If all characters, name and value can be placed into current line not exceeding line_size,
	///   then encodes as one line, otherwise does folding
	/// 
	/// In case of folding all parameters would be terminated with ';' as required by rfc, but last one - will not. 
	/// If you need to write several header parameters - in loop add "; " after calling this method.
	template <class Destination, class NameRandomAccessIterator, class ValRandomAccessIterator>
	std::enable_if_t<
		ext::is_iterator_v<NameRandomAccessIterator> and ext::is_iterator_v<ValRandomAccessIterator>,
		std::size_t
	>
	encode_header_parameter_folded(
		Destination & dest, std::size_t cur_pos, std::size_t line_size,
		NameRandomAccessIterator name_first, NameRandomAccessIterator name_last,
		ValRandomAccessIterator  val_first,  ValRandomAccessIterator  val_last)
	{
		using namespace detail;
		using namespace encoding_tables;
		using encode_utils::estimate_count;
			
		const std::size_t name_size = name_last - name_first;
		if (name_size == 0) throw std::invalid_argument("encode_header_parameter_folded: empty name");

		// name length + '*=' + encoding prefix + ';' + 3 chars at least should be placeable into string line.
		// we must be able to write: <name><num_prefix>=<enc_prefix><one escaped symbol>;
		if (name_size + parameter_encoding_prefix_size + 15 >= line_size - linebreak_size)
			throw std::invalid_argument("encode_header_parameter_folded: can't encode header with such arguments");

		// determine which way to encode header parameter.
		// on current step do not count cur_pos, we only choosing encoding way,
		// next steps, if needed - will split on next line and in case of simple header - will write full of it.
		std::size_t avail = line_size - name_size - linebreak_size - 2; // -2 для '=' и ';'
		std::size_t count = val_last - val_first;
		
		// needed more than avail - it's folding anyway,
		// otherwise try more simple schemes
		if (count < avail)
		{
			// count how much will get encoding without quoting
			auto est_count = estimate_count(parameter_unqouted_array, val_first, val_last);
			// all characters can be written as is, and there is enough space - write as is
			if (est_count == count)
				return encode_simple_header_parameter(dest, false, cur_pos, line_size, name_first, name_last, val_first, val_last);

			// can we write as is with quoting?
			bool quoted_simple = avail >= count + 2 and // add +2 for quotes
				count == estimate_count(parameter_qouted_array, val_first, val_last);
			if (quoted_simple)
				return encode_simple_header_parameter(dest, true, cur_pos, line_size, name_first, name_last, val_first, val_last);
		}

		return encode_folded_header_parameter(dest, cur_pos, line_size, name_first, name_last, val_first, val_last);
	}

	/// range overload
	template <class Destination, class NameRandomAccessRange, class ValRandomAccessRange>
	std::size_t encode_header_parameter_folded(
		Destination & dest, std::size_t curPos, std::size_t lineSize,
		const NameRandomAccessRange & name, const ValRandomAccessRange & value)
	{
		auto name_lit = ext::as_literal(name);
		auto val_lit  = ext::as_literal(value);

		return encode_header_parameter_folded(
			dest, curPos, lineSize,
			boost::begin(name_lit), boost::end(name_lit),
			boost::begin(val_lit), boost::end(val_lit)
		);
	}





	/// Encodes header parameter according to rfc 2231, MIME header parameter
	/// https://tools.ietf.org/html/rfc2231
	/// https://en.wikipedia.org/wiki/MIME#Content-Disposition
	/// * sink                    - there result would be written
	/// * cur_pos                 - current line position
	/// * line_size               - maximum line size
	/// * [name_first; name_last) - header name, must not be empty
	/// * [val_first; val_last)   - header value, must not be empty
	///
	/// This version does not folds at all(see encode_header_parameter_folded above), 
	/// but otherwise follows rfc 2231, can be used with protocols not imposing folding, for example, http.
	/// 
	/// This function will not add ';' nor newline
	template <class Destination, class NameRandomAccessIterator, class ValRandomAccessIterator>
	std::enable_if_t<ext::is_iterator_v<NameRandomAccessIterator> and ext::is_iterator_v<ValRandomAccessIterator>>
	encode_header_parameter(Destination & dest,
		NameRandomAccessIterator name_first, NameRandomAccessIterator name_last,
		ValRandomAccessIterator  val_first,  ValRandomAccessIterator  val_last)
	{
		using namespace encoding_tables;
		using namespace encode_utils;
		
		const std::size_t name_size = name_last - name_first;
		const std::size_t val_size = val_last - val_first;
		if (name_size == 0) throw std::invalid_argument("encode_header_parameter_folded: empty name");

		// determine which way to encode header parameter.
		if (val_size == estimate_count(parameter_unqouted_array, val_first, val_last))
		{
			// case: <name>=SomeThing
			write_string(dest, name_first, name_last);
			write_string(dest, "=");
			write_string(dest, val_first, val_last);
		}
		else if (val_size == estimate_count(parameter_unqouted_array, val_first, val_last))
		{
			// case: <name>="Some thing"
			write_string(dest, name_first, name_last);
			write_string(dest, "=");
			write_string(dest, "\"");
			write_string(dest, val_first, val_last);
			write_string(dest, "\"");
		}
		else
		{
			// case: <name>*=Some%20thing
			write_string(dest, name_first, name_last);
			write_string(dest, "*=");
			write_string(dest, parameter_encoding_prefix, parameter_encoding_prefix_size);
			quote(dest, parameter_char, parameter_unqouted_array, val_first, val_last);
		}
	}

	/// range overload
	template <class Destination, class NameRandomAccessRange, class ValRandomAccessRange>
	std::enable_if_t<std::conjunction_v<ext::is_range<NameRandomAccessRange>, ext::is_range<ValRandomAccessRange>>>
	encode_header_parameter(Destination & dest, const NameRandomAccessRange & name, const ValRandomAccessRange & value)
	{
		auto name_lit = ext::as_literal(name);
		auto val_lit = ext::as_literal(value);

		return encode_header_parameter(
			dest,
			boost::begin(name_lit), boost::end(name_lit),
			boost::begin(val_lit), boost::end(val_lit)
		);
	}

} // namespace ext::netlib::mime
