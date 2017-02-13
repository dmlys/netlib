#include <stdexcept>
#include <boost/regex.hpp>

#include <ext/netlib/parse_url.hpp>
#include <ext/netlib/codecs/url_encoding.hpp>

namespace ext {
namespace netlib
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

	parsed_url parse_url(const std::string & url)
	{
		parsed_url result;
		if (parse_url(url, result)) return result;

		throw std::runtime_error("parse_uri failure");
	}


	bool parse_url(const std::string & url, parsed_url & res)
	{
		boost::smatch match;
		bool success = boost::regex_match(url, match, url_regex);
		if (not success) return false;

		res.schema = match[1];
		res.user   = match[2];
		res.pass   = match[3];
		res.host   = match[4];
		res.port   = match[5];

		res.path   = match[6];
		res.query  = match[7];
		res.frag   = match[8];

		return true;
	}
}}
