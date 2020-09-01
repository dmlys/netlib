#pragma once
#include <string>
#include <string_view>

namespace ext::net::http
{
	/// Parses regular HTTP header value(MIME headers not supported).
	/// Extracts header value into value, and all parameters into params string
	/// In practice - splits by ',', trims both result string values.
	/// Returns true if header_str has more input, false if header_str depleted.
	/// parsing examples:
	///   some string                             -> [("some string", "")]
	///   val; par = 123                          -> [("val"), ("par = 123")]
	///   br;q=1.0, gzip;q=0.8, *;q=0.1; some=123 -> [("br", "q=1.0"), ("gzip", "q=0.8"), ("*", "q=0.1; some=123")]
	///
	/// Typical usage:
	///   while(parse_header_value(header_str, value, parstr))
	///   {
	///       do something with value and parstr
	///   }
	bool parse_header_value(std::string & header_str, std::string & value, std::string & params); // can throw bad_alloc on string assignment
	bool parse_header_value(std::string_view & header_str, std::string_view & value, std::string_view & params) noexcept;

	/// Parses and extracts specific value from header_str, returns true if value was found, false otherwise
	/// Typical usage:
	///   if (extract_header_value(header_str, "gzip", parstr) and extract_header_parameter(parstr, "q", parval))
	///   {
	///       do something with parval and fact that gzip is present
	///   }
	bool extract_header_value(std::string_view header_str, std::string_view value, std::string & params); // can throw bad_alloc on string assignment
	bool extract_header_value(std::string_view header_str, std::string_view value, std::string_view & params) noexcept;

	/// Parses regular HTTP header value parameters(MIME headers not supported).
	/// Extracts header parameter name into name and value into value,
	/// In practice - splits by ';' and '=', trims both result string values.
	/// Returns true if par_str has more input, false if par_str depleted.
	/// parsing examples:
	///   par1=val1; par2 = val2                  -> [("par1", "val1"), ("par2", "val2")]
	///   q=1.0; vopr                             -> [("q"), ("1.0"), ("vopr", "")]
	///
	/// Typical usage:
	///   while(parse_header_parameter(par_str, name, value))
	///   {
	///       do something with name and value
	///   }
	bool parse_header_parameter(std::string & par_str, std::string & name, std::string & value); // can throw bad_alloc on string assignment
	bool parse_header_parameter(std::string_view & par_str, std::string_view & name, std::string_view & value) noexcept;

	/// Parses and extracts specific parameter from par_str, returns true if parameter was found, false otherwise
	/// Typical usage:
	///   if (extract_header_value(header_str, "gzip", parstr) and extract_header_parameter(parstr, "q", parval))
	///   {
	///       do something with parval and fact that gzip is present
	///   }
	bool extract_header_parameter(std::string_view par_str, std::string_view name, std::string & value); // can throw bad_alloc on string assignment
	bool extract_header_parameter(std::string_view par_str, std::string_view name, std::string_view & value) noexcept;

	/// Parses regular HTTP query string, both from url or POST request: name=value&name=value&name=value ...
	/// Extracts both name and value. In practice splits by '&' and '=', trims both result string values.
	/// Returns true if query_str has more input, false if query_str depleted.
	/// NOTE: this function does not do any form of url decoding.
	///
	/// parsing examples:
	///   name=value                           -> [("name", "value"]
	///   name1=value1&name2&=value3           -> [("name1", "value1"), ("", "name2"), ("", "value3")]
	///
	/// Typical usage:
	///   while (parse_query(query_str, name, value)
	///   {
	///       do something with name and value
	///   }
	bool parse_query(std::string & query_str, std::string & name, std::string & value); // can throw bad_alloc on string assignment
	bool parse_query(std::string_view & query_str, std::string_view & name, std::string_view & value) noexcept;

	/// Parses and extracts specific parameter from query_str, return true if parameter was found, false otherwise
	///
	/// Typical usage:
	///   if (extract_query(query_str, "user", userval))
	///   {
	///       do something with userval and fact that user argument is given
	///   }
	bool extract_query(std::string_view qurey_str, std::string_view name, std::string & value); // can throw bad_alloc on string assignment
	bool extract_query(std::string_view qurey_str, std::string_view name, std::string_view & value) noexcept;

	/// parses weight string, which is basicly a float number written in C locale
	/// if parsing fails(not a number, etc) - returns invval
	double parse_weight(std::string_view str, double invval = 0.0);
	
	/// parses and extracts weight parameter from field string, returns it.
	/// Typical usage:
	///   std::string_view accept_header = ...
	///   double default_weight = extract_weight(accept_header, "*");
	///   double   plain_weight = extract_weight(accept_header, "text/plain");
	///   double    html_weight = extract_weight(accept_header, "text/html");
	double extract_weight(std::string_view field, std::string_view name, double defval = 0.0);
	
}
