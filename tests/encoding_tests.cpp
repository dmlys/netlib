#include <ext/net/mime/wwwformurl-encoding.hpp>
#include <boost/test/unit_test.hpp>
#include "test_files.h"

BOOST_AUTO_TEST_SUITE(encoding_tests)

BOOST_AUTO_TEST_CASE(wwwformurl_encoding_test)
{
	std::string text, result, expected;
	text = "simple текст with spaces";
	result = ext::net::encode_wwwformurl(text);

	expected = "simple+%D1%82%D0%B5%D0%BA%D1%81%D1%82+with+spaces";
	BOOST_CHECK_EQUAL(result, expected);

	result = ext::net::decode_wwwformurl(result);
	expected = result;
	BOOST_CHECK_EQUAL(result, expected);

	// mixed input
	text = "simple+текст+with+spaces";
	result = ext::net::decode_wwwformurl(text);
	expected = "simple текст with spaces";
	BOOST_CHECK_EQUAL(result, expected);

	text = "simple++";
	result = ext::net::decode_wwwformurl(text);
	expected = "simple  ";
	BOOST_CHECK_EQUAL(result, expected);
}

BOOST_AUTO_TEST_SUITE_END()
