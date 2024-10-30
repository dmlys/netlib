#pragma once
#include <string>
#include <string_view>

namespace ext::net
{
	struct parsed_url
	{
		std::string schema;
		std::string user, pass;
		std::string host, port;
		std::string path, query, frag;
	};


	/// parses url. parsing is done via regex and is somewhat permissive.
	/// url is: <schema>://<user>:<pass>@<host>:<port>/<path>?<query>#<frag>
	/// most parts are optional.
	/// 
	/// some examples:
	/// * https://user:123@httpbin.org:83/path/text.log?par=123&var=str#frag
	/// * //user:123@httpbin.org:83/path/text.log?par=123&var=str#frag
	/// * //httpbin.org:83/path/text.log
	/// * /path/text.log
	/// * path/text.log
	parsed_url parse_url(std::string_view url);
	bool parse_url(std::string_view url, parsed_url & res);
}
