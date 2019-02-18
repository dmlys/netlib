#pragma once
#include <ext/config.hpp>
#include <ext/enum_bitset.hpp>

namespace ext::net::mime
{
	enum mail_encoding : unsigned
	{
		bit7,               // Content-Transfer-Encoding: 7bit              -> all mail body characters have to be ascii( < 127 and not control ones) and line limit restrictions still applies(at most 1000 characters)
		bit8,               // Content-Transfer-Encoding: 8bit              -> all mail body characters can have any value, but line limit restrictions still applies(at most 1000 characters), requires 8BITMIME extension
		binary,             // Content-Transfer-Encoding: binary            -> mail body have no restrictions, requires BINARYMIME extension
		quoted_printable,   // Content-Transfer-Encoding: quoted-printable  -> mail body text is encoded with quoted-printable encoding
		base64,             // Content-Transfer-Encoding: base64            -> mail body text is encoded with base64 encoding
	};

	using mail_encoding_bitset = ext::enum_bitset<mail_encoding, 5>;


	inline const char * to_string(mail_encoding enc)
	{
		switch (enc)
		{
			case bit7:              return "7bit";
			case bit8:              return "8bit";
			case binary:            return "binary";
			case quoted_printable:  return "quoted-printable";
			case base64:            return "base64";

			default: EXT_UNREACHABLE();
		}
	}
}
