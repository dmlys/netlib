#include <ext/net/http_parser.hpp>
#include <ext/net/http/parse_header.hpp>
#include <boost/test/unit_test.hpp>
#include "test_files.h"

BOOST_AUTO_TEST_SUITE(http_parse_tests)

BOOST_AUTO_TEST_CASE(parse_response_test)
{
	std::string text;
	LoadTestFile("test-files/post.example.txt", text);

	std::istringstream is(text);
	std::string method, url, body;
	std::tie(method, url, body) = ext::net::parse_http_request(is);

	BOOST_CHECK(method == "POST");
	BOOST_CHECK(url    == "/test/index.html");
	BOOST_CHECK(body   == "licenseID=string&content=string&/paramsXML=string");
}

BOOST_AUTO_TEST_CASE(parse_header_test)
{
	using namespace ext::net::http;
	std::string_view text;
	std::string_view value, parstr, parval;

	text = "value1, value2";
	parse_header_value(text, value, parstr);
	BOOST_CHECK_EQUAL(value, "value1");
	BOOST_CHECK_EQUAL(parstr, "");
	parse_header_value(text, value, parstr);
	BOOST_CHECK_EQUAL(value, "value2");
	BOOST_CHECK_EQUAL(parstr, "");


	text = "deflate ; q=0.5 , gzip;q=1";

	parse_header_value(text, value, parstr);
	BOOST_CHECK_EQUAL(value, "deflate");
	BOOST_CHECK_EQUAL(parstr, "q=0.5");
	parse_header_value(text, value, parstr);
	BOOST_CHECK_EQUAL(value, "gzip");
	BOOST_CHECK_EQUAL(parstr, "q=1");

	text = "deflate ; q=0.5 , gzip;q=1";
	BOOST_CHECK(not extract_header_value(text, "def", parstr));
	BOOST_CHECK(extract_header_value(text, "deflate", parstr));
	BOOST_CHECK_EQUAL(parstr, "q=0.5");

	text = "deflate ; q=0.5 , gzip;q=1";
	BOOST_CHECK(extract_header_value(text, "gzip", parstr));
	BOOST_CHECK(extract_header_parameter(parstr, "q", parval));
	BOOST_CHECK_EQUAL(parval, "1");
}

BOOST_AUTO_TEST_CASE(parse_query_test)
{
	using namespace ext::net::http;
	std::string_view text;
	std::string_view name, value;

	text = "user=palps&action=doit&treason&=duel";
	parse_query(text, name, value);
	BOOST_CHECK_EQUAL(name, "user");
	BOOST_CHECK_EQUAL(value, "palps");
	parse_query(text, name, value);
	BOOST_CHECK_EQUAL(name, "action");
	BOOST_CHECK_EQUAL(value, "doit");
	parse_query(text, name, value);
	BOOST_CHECK_EQUAL(name, "");
	BOOST_CHECK_EQUAL(value, "treason");
	parse_query(text, name, value);
	BOOST_CHECK_EQUAL(name, "");
	BOOST_CHECK_EQUAL(value, "duel");

	text = "user=palps&action=doit&treason&=duel";
	BOOST_CHECK(extract_query(text, "user", value));
	BOOST_CHECK_EQUAL(value, "palps");
	BOOST_CHECK(extract_query(text, "action", value));
	BOOST_CHECK_EQUAL(value, "doit");
	BOOST_CHECK(extract_query(text, "", value));
	BOOST_CHECK_EQUAL(value, "treason");
}

BOOST_AUTO_TEST_CASE(set_header_value_test)
{
	using namespace ext::net::http;
	std::string header;
	
	header = "br;q=1.0";
	set_header_value_list_item(header, "gzip", "q=1.9");
	BOOST_CHECK_EQUAL(header, "br;q=1.0, gzip;q=1.9");
	
	header = "gzip;q=0.8, *;q=0.1; some=123";
	set_header_value_list_item(header, "gzip", "");
	BOOST_CHECK_EQUAL(header, "gzip, *;q=0.1; some=123");
	
	header = "gzip, br;q=1.0";
	set_header_value_list_item(header, "gzip", "q=1.1");
	BOOST_CHECK_EQUAL(header, "gzip;q=1.1, br;q=1.0");
	
	header = "br;q=1, gzip";
	set_header_value_list_item(header, "gzip", "q=1.1");
	BOOST_CHECK_EQUAL(header, "br;q=1, gzip;q=1.1");
}

BOOST_AUTO_TEST_SUITE_END()
