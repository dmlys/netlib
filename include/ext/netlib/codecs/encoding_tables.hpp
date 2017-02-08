#pragma once

namespace ext {
namespace netlib
{
	/// encoding tables used for different mime, http, etc encodings.
	/// if symbol is allowed - table element value holds representation value
	/// (usually it's symbol code itself, but there are exceptions)
	/// if symbol is not allowed - value == -1
	/// table size is 256
	namespace encoding_tables
	{
		/// table used for hex encoding: 0 - '0' ... 10 - 'A' ... 15 - 'F'
		extern const char hex_encoding_array[16];
		extern const char hex_decoding_array[256];

		/// email mime encodings.
		const char mime_qencoding_char = 61; // '='
		/// encoding table for qencoding, according to rfc 2047
		extern const char mime_qencoding_array[256];
		/// encoding table for quoted-printable, according to rfc 2047
		extern const char mime_quoted_printable_array[256];

		const char mime_parameter_char = 37; // '%'
		/// mime parameter encoding table for not quoted parameters, example filename=0*test.txt
		extern const char mime_parameter_unqouted_array[256];
		/// mime parameter ecndoing table for quoted parameters, example filename=0*"test file.txt"
		extern const char mime_parameter_qouted_array[256];

		/// http percent encoding table
		const char percent_char = 37; //'%'
		extern const char percent_encoding_array[256];
	}
}}
