#include <string>
#include <string_view>
#include <stdexcept>
#include <boost/regex.hpp>

#include <ext/net/parse_url.hpp>
#include <ext/net/mime/url_encoding.hpp>

namespace ext::net
{
	namespace
	{
		static boost::regex url_regex {
			"  (?: ( [^:/?#]+ ): )?  " // schema
			"  (?: //                " // if starts with '//' we have host:port part
			"      (?:               "   // optional user_info part,
			"        ( [^/?#:@]*)    "   // user_name
			"        (?: : ([^@]*))? "   // password, optional
			"      @)?               "   // user_info must end with @
			"    ( [^/?#:]* )        " // host
			"    (?: : (\\d+) )?     " // port
			"  )?                    "
			"  ( [^?#]* )            " // path
			"  (?: \\? ( [^#]*) )?   " // query
			"  (?: \\# (.*) )?       " // fragment
			, 
			
			boost::regex_constants::perl     |
			boost::regex_constants::optimize |
			boost::regex_constants::mod_x
		};
	}

	parsed_url parse_url(std::string_view url)
	{
		parsed_url result;
		if (parse_url(url, result))
			return result;

		throw std::runtime_error("parse_uri failure");
	}


	bool parse_url(std::string_view url, parsed_url & res)
	{
		boost::cmatch match;
		
		auto * first = url.data();
		auto * last  = first + url.size();
		bool success = boost::regex_match(first, last, match, url_regex);
		if (not success)
			return false;

		#define assign_match(n) .assign(match[n].begin(), match[n].end())
		
		res.schema  assign_match(1);
		res.user    assign_match(2);
		res.pass    assign_match(3);
		res.host    assign_match(4);
		res.port    assign_match(5);

		res.path    assign_match(6);
		res.query   assign_match(7);
		res.frag    assign_match(8);

		#undef assign_match
		
		return true;
	}
}
