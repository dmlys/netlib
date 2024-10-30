#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <ext/net/parse_url.hpp>


BOOST_AUTO_TEST_CASE(parse_url_tests)
{
	using ext::net::parsed_url;
	using ext::net::parse_url;
	
	parsed_url parsed;
	parsed = parse_url("path");	
	BOOST_CHECK_EQUAL(parsed.path, "path");
	BOOST_CHECK_EQUAL(parsed.host, "");
	
	parsed = parse_url("/path");
	BOOST_CHECK_EQUAL(parsed.path, "/path");
	BOOST_CHECK_EQUAL(parsed.host, "");
	
	parsed = parse_url("//host");
	BOOST_CHECK_EQUAL(parsed.host, "host");
	BOOST_CHECK_EQUAL(parsed.path, "");
	
	parsed = parse_url("path#frag");
	BOOST_CHECK_EQUAL(parsed.host, "");
	BOOST_CHECK_EQUAL(parsed.path, "path");
	BOOST_CHECK_EQUAL(parsed.frag, "frag");
	
	parsed = parse_url("https://user:pass@host:8181/path?arg=12#frag");
	BOOST_CHECK_EQUAL(parsed.schema, "https");
	BOOST_CHECK_EQUAL(parsed.user, "user");
	BOOST_CHECK_EQUAL(parsed.pass, "pass");
	BOOST_CHECK_EQUAL(parsed.host, "host");
	BOOST_CHECK_EQUAL(parsed.port, "8181");
	BOOST_CHECK_EQUAL(parsed.path, "/path");
	BOOST_CHECK_EQUAL(parsed.query, "arg=12");
	BOOST_CHECK_EQUAL(parsed.frag, "frag");
	
}
