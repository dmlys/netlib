#pragma once
#include <ext/config.hpp>
#include <ext/enum_bitset.hpp>

namespace ext::netlib::smtp
{
	enum smtp_extensions : unsigned
	{
		// well known extensions
		starttls,
		login_auth,
		login_plain,

		bit8_mime,
		binary_mime,
		smtp_utf8,
		chunking,
	};

	using smtp_extensions_bitset = ext::enum_bitset<smtp_extensions, 7>;

	inline const char * to_string(smtp_extensions extension)
	{
		switch (extension)
		{
			case starttls:     return "STARTTLS";
			case login_auth:   return "AUTH LOGIN";
			case login_plain:  return "AUTH PLAIN";

			case bit8_mime:    return "8BITMIME";
			case binary_mime:  return "BINARYMIME";
			case smtp_utf8:    return "SMTPUTF8";
			case chunking:     return "CHUNKING";

			default: EXT_UNREACHABLE();
		}
	}
}

namespace ext::netlib
{
	using smtp::smtp_extensions;
	using smtp::smtp_extensions_bitset;
}
