#pragma once
#include <cstddef>

namespace ext::net::mime
{
	/// encoding tables used for different mime encodings.
	/// if symbol is allowed - table element value holds representation value
	/// (usually it's symbol code itself, but there are exceptions)
	/// if symbol is not allowed - value == -1
	/// table size usually is 256
	namespace encoding_tables
	{
		/// table used for hex encoding: 0 - '0' ... 10 - 'A' ... 15 - 'F'
		extern const char hex_encoding_array[16];
		extern const char hex_decoding_array[256];

		/// http percent encoding table
		const char percent_char = 37; //'%'
		extern const char percent_encoding_array[256];
		extern const char wwwformurl_encoding_array[256]; // encoding array for application/x-www-form-urlencoded
		extern const char wwwformurl_decoding_array[256]; // decoding array for application/x-www-form-urlencoded

		constexpr std::size_t MailMinLineSize = 20;
		constexpr std::size_t MailMaxLineSize = 1000;     // including \r\n
		constexpr std::size_t MailDefaultLineSize = 80;   // including \r\n
		constexpr std::size_t MailQPDefaultLineSzie = 76; // excluding \r\n

		constexpr auto qencoded_prefix = "=?utf-8?q?";
		constexpr auto bencoded_prefix = "=?utf-8?b?";
		constexpr auto encoded_suffix = "?=";
		constexpr std::size_t qencoded_prefix_size = 10;  // std::strlen(qencoded_prefix);
		constexpr std::size_t bencoded_prefix_size = 10;  // std::strlen(bencoded_prefix);
		constexpr std::size_t encoded_suffix_size = 2;    // std::strlen(encoded_suffix);

		constexpr auto linebreak = "\r\n ";
		constexpr std::size_t linebreak_size = 2;         // std::strlen(linebreak);
		constexpr std::size_t linebreak_prefix_size = 1;

		constexpr auto parameter_encoding_prefix = "utf-8''";
		constexpr auto parameter_linebreak = ";\r\n ";
		constexpr std::size_t parameter_encoding_prefix_size = 7; // std::strlen(parameter_encoding_prefix);
		constexpr std::size_t parameter_separator_size = 1;       // std::strlen(";");
		constexpr std::size_t parameter_linebreak_size = 4;       // std::strlen(parameter_linebreak);

			
		/// email mime encodings:

		const char qencoding_char = 61; // '='
		/// encoding table for qencoding, according to rfc 2047
		extern const char qencoding_array[256];

		const char quoted_printable_char = 61; // '='
		/// encoding table for quoted-printable, according to rfc 2047
		extern const char quoted_printable_array[256];

		const char parameter_char = 37; // '%'
		/// mime parameter encoding table for not quoted parameters, example filename=0*test.txt
		extern const char parameter_unqouted_array[256];
		/// mime parameter ecndoing table for quoted parameters, example filename=0*"test file.txt"
		extern const char parameter_qouted_array[256];
	}

	using encoding_tables::MailDefaultLineSize;
	using encoding_tables::MailMaxLineSize;
	using encoding_tables::MailMinLineSize;
	using encoding_tables::MailQPDefaultLineSzie;
}
