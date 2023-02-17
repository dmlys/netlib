#pragma once
#include <string>
#include <string_view>
#include <tuple>
#include <array>
#include <algorithm>

#include <ext/utility.hpp>


namespace ext::net::http
{
	void crack_wwwformurl_query_impl(std::string_view text, const std::string_view * names, std::string * values, std::size_t N);
	void crack_url_query_impl(std::string_view text, const std::string_view * names, std::string * values, std::size_t N);
	
	//template <std::size_t N>
	//inline auto crack_wwwformurl_query(std::string_view text, const std::array<std::string_view, N> & names) -> std::array<std::string, N>
	//{
	//	std::array<std::string, N> values;
	//	crack_wwwformurl_query_impl(text, names.data(), values.data(), N);
	//	return values;
	//}

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
		std::array<std::string, N> values;
		crack_wwwformurl_query_impl(text, names.data(), values.data(), N);
		
		return ext::as_tuple(std::move(values));
	}

	//template <std::size_t N>
	//inline auto crack_url_query(std::string_view text, const std::array<std::string_view, N> & names) -> std::array<std::string, N>
	//{
	//	std::array<std::string, N> values;
	//	crack_url_query_impl(text, names.data(), values.data(), N);
	//	return values;
	//}

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
		std::array<std::string, N> values;
		crack_url_query_impl(text, names.data(), values.data(), N);
		
		return ext::as_tuple(std::move(values));
	}
}
