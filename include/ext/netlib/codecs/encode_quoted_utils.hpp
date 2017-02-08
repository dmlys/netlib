#pragma once
#include <cstddef>
#include <stdexcept>
#include <utility>
#include <tuple> // for std::tie uses
#include <ext/utf8utils.hpp>
#include <ext/config.hpp>

namespace ext {
namespace netlib
{
	namespace encoding_tables
	{
		static_assert(CHAR_BIT == 8, "byte is not octet");

		/// table used for hex encoding: 0 - '0' ... 10 - 'A' ... 15 - 'F'
		extern const char hex_encoding_array[16];
		extern const char hex_decoding_array[256];
	}

	/// help functions for encoding chars using different encodings: mime, http, etc.
	/// those print some characters as is, others are quoted as <qchar><hex1><hex2>,
	/// for example '=20'. Such encodings are qencoding, http percent encoding, etc.
	/// 
	/// functions take encoding table, describing what symbols should be quoted который описывают как кодировать символы
	/// if table element is < 0 - symbol should be quoted, otherwise printed by element value.
	/// 
	/// all input text is assumed utf-8.
	namespace encode_utils
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
			ch = encoding_tables::hex_decoding_array[ch];
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

		/// encodes input utf-8 text [first;last) inot out, not more than max_output,
		/// and not breaking utf-8 multi-byte sequences encoding is done using encode_arr and qchar
		/// 
		/// algorithm can write less than max_output, 
		/// if writing last symbol would break utf-8 or <qc><h1><h2> sequence
		///
		/// returns position pair of iterator where input stopped and number or written chars.
		/// works only with utf-8 text
		template <class Iterator, class OutputIterator>
		std::pair<Iterator, std::size_t> encode_quoted_bounded
			(char qchar, const char * encode_arr, std::size_t max_output,
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

			return {first, written};
		}
	}
}}
