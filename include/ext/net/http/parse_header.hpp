#pragma once
#include <string>
#include <string_view>

namespace ext::net::http
{
	/// parses regular HTTP header value(MIME headers not supported).
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

	/// parses and extracts specific value from header_str, returns true if value was found, false otherwise
	/// Typical usage:
	///   if (extract_header_value(header_str, "gzip", parstr) and extract_header_parameter(parstr, "q", parval))
	///   {
	///       do something with parval and fact that gzip is present
	///   }
	bool extract_header_value(std::string_view header_str, std::string_view value, std::string & params); // can throw bad_alloc on string assignment
	bool extract_header_value(std::string_view header_str, std::string_view value, std::string_view & params) noexcept;

	/// parses regular HTTP header value parameters(MIME headers not supported).
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

	/// parses and extracts specific parameter from par_str, returns true if parameter was found, false otherwise
	/// Typical usage:
	///   if (extract_header_value(header_str, "gzip", parstr) and extract_header_parameter(parstr, "q", parval))
	///   {
	///       do something with parval and fact that gzip is present
	///   }
	bool extract_header_parameter(std::string_view par_str, std::string_view name, std::string & value); // can throw bad_alloc on string assignment
	bool extract_header_parameter(std::string_view par_str, std::string_view name, std::string_view & value) noexcept;
}
