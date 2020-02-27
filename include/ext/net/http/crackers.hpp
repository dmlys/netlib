#pragma once
#include <string>
#include <string_view>
#include <tuple>
#include <array>
#include <algorithm>

#include <ext/utility.hpp>
#include <ext/net/http/parse_header.hpp>
#include <ext/net/mime/url_encoding.hpp>
#include <ext/net/mime/wwwformurl-encoding.hpp>


namespace ext::net::http
{
	template <std::size_t N>
	auto crack_wwwformurl_query_impl(std::string_view text, const std::array<std::string_view, N> & names)
	{
		using result_type = ext::make_nth_tuple_t<std::string, N>;
		result_type result;

		auto names_first = names.begin();
		auto names_last  = names.end();

		std::string decoded_name;
		std::string_view name, value;
		while (parse_query(text, name, value))
		{
			decoded_name.clear();
			ext::net::decode_wwwformurl(name, decoded_name);

			auto it = std::find(names_first, names_last, decoded_name);
			if (it == names_last) continue;

			std::size_t index = it - names_first;
			ext::visit(result, index, [value](auto & dest) { ext::net::decode_wwwformurl(value, dest); });
		}

		return result;
	}

	/// Cracks application/x-www-form-urlencoded POST data, extracts values for given names and decodes them.
	/// Usage example:
	///   assert(std::string request == "user=joe&action=send+on+vacation")
	///   std::string user, action;
	///   std::tie(user, action) = crack_wwwformurl_query(request_text, "user", "action");
	///   assert(user == "joe");
	///   assert(action == "send on vacation");
	template <class ... Args>
	auto crack_wwwformurl_query(std::string_view text, const Args & ... args)
	{
		constexpr auto N = sizeof...(args);
		std::array<std::string_view, N> names = { args... };
		return crack_wwwformurl_query_impl(text, names);
	}

	template <std::size_t N>
	auto crack_url_query_impl(std::string_view text, const std::array<std::string_view, N> & names)
	{
		using result_type = ext::make_nth_tuple_t<std::string, N>;
		result_type result;

		auto names_first = names.begin();
		auto names_last  = names.end();

		std::string decoded_name;
		std::string_view name, value;
		while (parse_query(text, name, value))
		{
			decoded_name.clear();
			ext::net::decode_wwwformurl(name, decoded_name);

			auto it = std::find(names_first, names_last, decoded_name);
			if (it == names_last) continue;

			std::size_t index = it - names_first;
			ext::visit(result, index, [value](auto & dest) { ext::net::decode_url(value, dest); });
		}

		return result;
	}

	/// Cracks url query string, extracts values for given names and decodes them.
	/// Usage example:
	///   assert(std::string request == "user=joe&action=send%20on%20vacation")
	///   std::string user, action;
	///   std::tie(user, action) = crack_wwwformurl_query(request_text, "user", "action");
	///   assert(user == "joe");
	///   assert(action == "send on vacation");
	template <class ... Args>
	auto crack_url_query(std::string_view text, const Args & ... args)
	{
		constexpr auto N = sizeof...(args);
		std::array<std::string_view, N> names = { args... };
		return crack_url_query_impl(text, names);
	}
}
