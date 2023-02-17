#include <ext/net/http/crackers.hpp>

#include <ext/net/http/parse_header.hpp>
#include <ext/net/mime/url_encoding.hpp>
#include <ext/net/mime/wwwformurl-encoding.hpp>

namespace ext::net::http
{
	void crack_wwwformurl_query_impl(std::string_view text, const std::string_view * names, std::string * values, std::size_t N)
	{
		auto names_first = names;
		auto names_last  = names + N;

		std::string decoded_name;
		std::string_view name, value;
		while (parse_query(text, name, value))
		{
			decoded_name.clear();
			ext::net::decode_wwwformurl(name, decoded_name);

			auto it = std::find(names_first, names_last, decoded_name);
			if (it == names_last) continue;

			std::size_t index = it - names_first;
			ext::net::decode_wwwformurl(value, values[index]);
		}
	}
	
	void crack_url_query_impl(std::string_view text, const std::string_view * names, std::string * values, std::size_t N)
	{
		auto names_first = names;
		auto names_last  = names + N;

		std::string decoded_name;
		std::string_view name, value;
		while (parse_query(text, name, value))
		{
			decoded_name.clear();
			ext::net::decode_url(name, decoded_name);

			auto it = std::find(names_first, names_last, decoded_name);
			if (it == names_last) continue;

			std::size_t index = it - names_first;
			ext::net::decode_url(value, values[index]);
		}
	}
}

