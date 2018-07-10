#pragma once
#include <cstddef>
#include <stdexcept>
#include <tuple> // for std::tie uses
#include <ext/type_traits.hpp> // for is_iterator
#include <ext/config.hpp>
#include <ext/utf8utils.hpp>

// for write_string impl
#include <ext/range.hpp>
#include <ext/type_traits.hpp>
#include <ext/iostreams/utility.hpp>

namespace ext::netlib
{
	namespace mime::encoding_tables
	{
		static_assert(CHAR_BIT == 8, "byte is not octet");

		/// table used for hex encoding: 0 - '0' ... 10 - 'A' ... 15 - 'F'
		extern const char hex_encoding_array[16];
		extern const char hex_decoding_array[256];
	}

	/// helper functions for encoding chars using different encodings http
	/// those print some characters as is, others are quoted as <qchar><hex1><hex2>,
	/// for example '=20'. Such encodings are qencoding, http percent encoding, etc.
	/// 
	/// functions take encoding table, describing what symbols should be quoted который описывают как кодировать символы
	/// if table element is < 0 - symbol should be quoted, otherwise printed by element value.
	/// 
	/// all input text is assumed utf-8.
	namespace mime::encode_utils
	{
		/// base exception for all quoted errors
		class quoted_exception : public std::runtime_error 
		{
		public:
			quoted_exception(const char * msg) : std::runtime_error(msg) {}
		};

		/// input has not enough input, last group is not full, like %3
		class not_enough_input : public quoted_exception
		{
		public:
			not_enough_input() : quoted_exception("encode_utils::unquote: not full quote group") {}
		};

		/// input has quoted group with non hex char, like %3Z
		class non_hex_char : public quoted_exception
		{
		public:
			non_hex_char() : quoted_exception("encode_utils::unquote: bad hex char in quote group") {}
		};


		/// size of temporary buffer on stack for functions
		constexpr std::size_t tmp_buffer_size = 256;

		/// truncates count by minimum, considering utf-8.
		/// if count > minimal - additionally truncates not full utf-8 sequnce
		template <class RandomAccessIterator>
		std::size_t utf8_trunc_count(std::size_t count, std::size_t minimum, RandomAccessIterator first)
		{
			if (count < minimum)
				return count;
			else
			{
				auto last = ext::utf8_utils::rtrunc(first, first + minimum);
				return last - first;
			}
		}

		/// quotes symbol ch, as '<qchar><hex1><hex2>', for example ' ' - '=20'
		template <class OutputIterator>
		inline OutputIterator quote_char(char qchar, unsigned char ch, OutputIterator out)
		{
			*out = qchar;
			*++out = encoding_tables::hex_encoding_array[ch / 16];
			*++out = encoding_tables::hex_encoding_array[ch % 16];
			return ++out;
		}

		inline char decode_nibble(char ch)
		{
			ch = encoding_tables::hex_decoding_array[static_cast<unsigned char>(ch)];
			if (ch >= 0) return ch;

			throw non_hex_char();
		}

		template <class Iterator>
		inline char unquote_char(Iterator & it)
		{
			return decode_nibble(*++it) * 16 + decode_nibble(*++it);
		}

		/// encodes input text [first; last) into out
		/// encoding is done using encode_arr and qchar
		template <class InputIterator, class OutputIterator>
		OutputIterator encode_quoted(char qchar, const char * encode_arr,
		                             InputIterator first, InputIterator last, OutputIterator out)
		{
			for (; first != last; ++first)
			{
				unsigned char uch = *first;
				char ch = encode_arr[uch];
				if (ch == -1)
					out = quote_char(qchar, uch, out);
				else
				{
					*out = ch;
					++out;
				}
			}

			return out;
		}

		/// decodes input quoted text [first; last) into out
		/// quoted char is char encoded as <qchar><hex1><hex2>
		/// 
		/// anything that is not quoted group is passed as is,
		/// in case of bad quoted groups - exceptions are thrown: not_enough_input, non_hex_char
		template <class RandomAccessIterator, class OutIterator>
		OutIterator decode_quoted(char qchar, RandomAccessIterator first, RandomAccessIterator last, OutIterator out)
		{
			// first process all chars except 3 last,
			// that way we can safely increment iterator 2 times,
			// for quoted chars, without need to check if we are past last.
			char ch;
			for (auto end = last - 3; first < end; ++first, ++out)
			{
				ch = *first;
				*out = ch != qchar ? ch : unquote_char(first);
			}

			// previous loop can go past end iterator, but not past last iterator.
			// check if last 3 characters is a quoted group
			assert(last - first <= 3);
			if ((ch = *first) == qchar)
			{
				// group is not full
				if (last - first < 3) throw not_enough_input();

				*out = unquote_char(first);
				++out;
			}

			// process trailing last - first <= 3
			assert(last - first <= 3);
			for (; first != last; ++first, ++out)
			{
				ch = *first;
				if (ch == qchar) throw not_enough_input();
				*out = ch;
			}

			return out;
		}

		/// encodes input utf-8 text [first;last) into out, not more than max_output,
		/// and not breaking utf-8 multi-byte sequences encoding is done using encode_arr and qchar
		/// 
		/// algorithm can write less than max_output, 
		/// if writing last symbol would break utf-8 or <qc><h1><h2> sequence
		///
		/// returns tuple of iterator where input stopped, where output stopped and number or written chars.
		/// works only with utf-8 text
		template <class Iterator, class OutputIterator>
		std::tuple<Iterator, OutputIterator, std::size_t>
		encode_quoted_bounded(
			char qchar, const char * encode_arr, std::size_t max_output,
			Iterator first, Iterator last, OutputIterator out)
		{
			char ch;
			unsigned char uch;
			std::size_t written = 0;

			while (first != last)
			{
				uch = ch = *first;
				auto len = ext::utf8_utils::seqlen(ch);
				ch = encode_arr[uch];

				if (len == 1)
				{
					if (ch >= 0)
					{
						++written;
						if (written > max_output)
						{
							--written;
							break;
						}

						*out = ch;
						++out; ++first;
						continue;
					}

					// ch < 0
					written += 3;
					if (written > max_output)
					{
						written -= 3;
						break;
					}

					out = quote_char(qchar, uch, out);
					++first;
					continue;
				}

				// len > 1
				auto estimate_size = len * 3;
				written += estimate_size;

				if (written > max_output)
				{
					written -= estimate_size;
					break;
				}
				
				switch (len)
				{
					default: EXT_UNREACHABLE();
					
					case 6:
						out = quote_char(qchar, *first, out);
						++first;
					case 5:
						out = quote_char(qchar, *first, out);
						++first;
					case 4:
						out = quote_char(qchar, *first, out);
						++first;
					case 3:
						out = quote_char(qchar, *first, out);
						++first;
					case 2:
						out = quote_char(qchar, *first, out);
						++first;
					case 1:
						out = quote_char(qchar, *first, out);
						++first;
				}
			}

			return {first, out, written};
		}
	} // namespace mime::encode_utils



	namespace mime::encode_utils
	{
		/// generic write_string functions, can write into:
		/// * iterators
		/// * containers
		/// * iostreams/boost::iostreams devices
		/// returns how much have been written

		template <class OutputIterator, class String>
		std::enable_if_t<ext::is_iterator_v<OutputIterator>, std::size_t>
		write_string(OutputIterator & out, const String & str)
		{
			auto str_lit = ext::as_literal(str);
			out = std::copy(begin(str_lit), end(str_lit), out);
			return str_lit.size();
		}

		template <class OutputConatiner, class String>
		std::enable_if_t<ext::is_container_v<OutputConatiner>, std::size_t>
		write_string(OutputConatiner & out, const String & str)
		{
			using std::begin; using std::end;
			auto str_lit = ext::as_literal(str);
			ext::append(out, begin(str_lit), end(str_lit));
			return str_lit.size();
		}

		template <class Sink, class String>
		std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
		write_string(Sink & sink, const String & str)
		{
			auto str_lit = ext::as_literal(str);
			ext::iostreams::write_string(sink, str_lit);
			return str_lit.size();
		}


		template <class OutputIterator, class Iterator>
		std::enable_if_t<ext::is_iterator_v<OutputIterator>, std::size_t>
		write_string(OutputIterator & out, Iterator first, Iterator last)
		{
			out = std::copy(first, last, out);
			return last - first;
		}

		template <class OutputConatiner, class Iterator>
		std::enable_if_t<ext::is_container_v<OutputConatiner>, std::size_t>
		write_string(OutputConatiner & out, Iterator first, Iterator last)
		{
			ext::append(out, first, last);
			return last - first;
		}

		template <class Sink, class Iterator>
		std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
		write_string(Sink & sink, Iterator first, Iterator last)
		{
			using char_type = typename std::iterator_traits<Iterator>::value_type;
			constexpr auto buffer_size = tmp_buffer_size;
			char_type buffer[buffer_size];
			std::size_t written = 0;

			do
			{
				auto step_size = std::min<std::size_t>(last - first, buffer_size);
				auto stop = first + step_size;
				std::copy(first, stop, buffer);

				ext::iostreams::write_all(sink, buffer, step_size);
				written += step_size;
				first = stop;

			} while (first < last);

			return written;
		}

		template <class Sink, class CharType>
		std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
		write_string(Sink & sink, const CharType * first, const CharType * last)
		{
			ext::iostreams::write_all(sink, first, last - first);
			return last - first;
		}
		
		
		template <class OutputIterator, class CharType>
		std::enable_if_t<ext::is_iterator_v<OutputIterator>, std::size_t>
		write_string(OutputIterator & out, const CharType * str, std::size_t len)
		{
			out = std::copy(str, str + len, out);
			return len;
		}

		template <class OutputConatiner, class CharType>
		std::enable_if_t<ext::is_container_v<OutputConatiner>, std::size_t>
		write_string(OutputConatiner & out, const CharType * str, std::size_t len)
		{
			ext::append(out, str, str + len);
			return len;
		}

		template <class Sink, class CharType>
		std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
		write_string(Sink & sink, const CharType * str, std::size_t len)
		{
			ext::iostreams::write_all(sink, str, len);
			return len;
		}


		/// more generic encode_quoted, works on:
		///  * output iterator
		///  * STL container
		///  * sink
		/// returns how much have been written
		
		template <class Destination, class Iterator>
		std::enable_if_t<ext::is_iterator_v<Destination>, std::size_t>
		inline quote(Destination & dest, char qchar, const char * encdoe_arr, Iterator first, Iterator last)
		{
			auto stopped = encode_quoted(qchar, encdoe_arr, first, last, dest);
			auto written = stopped - dest;
			dest = stopped;
			return written;
		}

		template <class Destination, class Iterator>
		std::enable_if_t<not ext::is_iterator_v<Destination>, std::size_t>
		quote(Destination & dest, char qchar, const char * encdoe_arr, Iterator first, Iterator last)
		{
			// encoding produce up to 3 times more than input
			constexpr auto buffer_size = tmp_buffer_size;
			constexpr auto step_size = buffer_size / 3;
			char buffer[buffer_size];
			std::size_t written = 0;

			while (first < last)
			{
				auto step_last = first + std::min<std::ptrdiff_t>(step_size, last - first);
				auto stopped = encode_quoted(qchar, encdoe_arr, first, step_last, buffer);
				
				written += write_string(dest, buffer, stopped - buffer);
				first = step_last;
			}

			return written;
		}


		/// more generic encode_quoted_bounded, works on:
		///  * output iterator
		///  * STL container
		///  * sink
		
		template <class Destination, class RandomAccessIterator>
		std::enable_if_t<ext::is_iterator_v<Destination>,
			std::tuple<RandomAccessIterator, std::size_t>>
		inline quote_bounded(
			Destination & dest, std::size_t max_output, char qchar, const char * encode_arr,
			RandomAccessIterator first, RandomAccessIterator last)
		{
			std::tie(first, max_output, dest) =
				encode_quoted_bounded(qchar, encode_arr, max_output, first, last, dest);

			return std::make_tuple(first, max_output);
		}

		template <class RandomAccessIterator, class Destination>
		std::enable_if_t<not ext::is_iterator_v<Destination>,
			std::tuple<RandomAccessIterator, std::size_t>>
		quote_bounded(
			Destination & dest, std::size_t max_output, char qchar, const char * encode_arr,
			RandomAccessIterator first, RandomAccessIterator last)
		{
			RandomAccessIterator stopped, stop;
			std::size_t written, write_count = max_output;

			constexpr auto buffer_size = tmp_buffer_size;
			char buffer[buffer_size];

			do {
				auto step_count = std::min<std::size_t>(last - first, buffer_size / 3);
				stop = first + step_count;

				std::tie(stopped, std::ignore, written) =
					encode_quoted_bounded(qchar, encode_arr, write_count, first, stop, buffer);

				write_string(dest, buffer, written);
				first = stopped;
				write_count -= written;

				// until we we have more to write and wrote all at this iteration
			} while (stop == stopped and first < last);

			return std::make_tuple(first, max_output - write_count);
		}
	}
}
