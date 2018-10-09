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

	BOOST_CHECK(method == "POST");
	BOOST_CHECK(url    == "/test/index.html");
	BOOST_CHECK(body   == "licenseID=string&content=string&/paramsXML=string");
}

using string_map = std::unordered_map<std::string, std::string>;
static string_map parse_http_header(std::string_view text)
{
	string_map result;
	std::string_view name, value;
	while (ext::netlib::parse_http_header(text, name, value))
		result[std::string(name)] = std::string(value);

	return result;
}

BOOST_AUTO_TEST_CASE(parse_http_header_test)
{
	std::string_view text;
	string_map result;

	text = "Content-Type: text/xml";
	result = parse_http_header(text);
	BOOST_CHECK_EQUAL(result["Content-Type"], "text/xml");

	text = "some string";
	result = parse_http_header(text);
	BOOST_CHECK_EQUAL(result[""], "some string");

	text = "some string; name=test";
	result = parse_http_header(text);
	BOOST_CHECK_EQUAL(result[""], "some string");
	BOOST_CHECK_EQUAL(result["name"], "test");

	text = "name: value; par=val";
	result = parse_http_header(text);
	BOOST_CHECK_EQUAL(result.count(""), 0 );
	BOOST_CHECK_EQUAL(result["name"], "value");
	BOOST_CHECK_EQUAL(result["par"], "val");	
}
