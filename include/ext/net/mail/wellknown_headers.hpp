#pragma once
#include <ext/net/mail/headers.hpp>

namespace ext::net::mail::headers
{
	inline auto date(std::time_t time)
	{
		return date_header("Date", time);
	}

	inline auto date(std::chrono::system_clock::time_point point)
	{
		return date_header("Date", point);
	}

	inline auto date()
	{
		return date_header("Date", std::time(nullptr));
	}

	template <class ValueString>
	inline auto mime_version(const ValueString & version)
	{
		return unstructured_header("MIME-Version", version);
	}

	inline auto mime_version()
	{
		return mime_version("1.0");
	}

	template <class ValueString>
	inline auto subject(const ValueString & value)
	{
		return unstructured_header("Subject", value);
	}

	template <class ValueStrings>
	inline auto from(const ValueStrings & values)
	{
		return address_header("From", values);
	}

	template <class ValueStrings>
	inline auto to(const ValueStrings & values)
	{
		return address_header("To", values);
	}

	template <class ValueStrings>
	inline auto cc(const ValueStrings & values)
	{
		return address_header("Cc", values);
	}

	template <class ValueStrings>
	inline auto bcc(const ValueStrings & values)
	{
		return address_header("Bcc", values);
	}

	template <class ValueStrings>
	inline auto reply_to(const ValueStrings & values)
	{
		return address_header("Reply-To", values);
	}
}
