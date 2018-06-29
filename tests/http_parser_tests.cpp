#include <ext/netlib/http_parser.hpp>
#include <boost/test/unit_test.hpp>
#include "test_files.h"

BOOST_AUTO_TEST_CASE(http_parser_response_test)
{
	std::string text;
	LoadTestFile("test-files/post.example.txt", text);

	std::istringstream is(text);
	std::string method, url, body;
	std::tie(method, url, body) = ext::netlib::parse_http_request(is);

	BOOST_CHECK(method == "post");
	BOOST_CHECK(url    == "/test/index.html");
	BOOST_CHECK(body   == "licenseID=string&content=string&/paramsXML=string");
}
