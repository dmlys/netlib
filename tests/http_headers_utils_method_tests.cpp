#include <ext/net/http/http_types.hpp>
#include <boost/test/unit_test.hpp>

using namespace ext::net;
using namespace ext::net::http;

BOOST_AUTO_TEST_SUITE(http_headers_utils_method_tests)

BOOST_AUTO_TEST_CASE(http_headers_append_test)
{
	http_headers_vector headers = 
	{
	    {{"Content-Encoding1"}, {"gzip"}},
	    {{"Content-Encoding2"}, {",gzip"}},
	    {{"Content-Encoding3"}, {", gzip"}},
	    {{"Content-Encoding4"}, {" , gzip"}},
	    {{"Content-Encoding5"}, {"deflate , gzip"}},
	};
	
	prepend_header_list_value(headers, "Content-Encoding1", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding1"), "zstd, gzip");
	
	prepend_header_list_value(headers, "Content-Encoding2", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding2"), "zstd,gzip");
	
	prepend_header_list_value(headers, "Content-Encoding3", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding3"), "zstd, gzip");
	
	prepend_header_list_value(headers, "Content-Encoding4", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding4"), "zstd , gzip");
	
	prepend_header_list_value(headers, "Content-Encoding5", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding5"), "zstd, deflate , gzip");
	
	prepend_header_list_value(headers, "Content-Encoding6", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding6"), "zstd");
	
	set_header(headers, "Test", "  ");
	prepend_header_list_value(headers, "Test", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Test"), "zstd");
}

BOOST_AUTO_TEST_CASE(http_headers_prepend_test)
{
	http_headers_vector headers = 
	{
	    {{"Content-Encoding1"}, {"gzip"}},
	    {{"Content-Encoding2"}, {"gzip,"}},
	    {{"Content-Encoding3"}, {"gzip, "}},
	    {{"Content-Encoding4"}, {"gzip , "}},
	    {{"Content-Encoding5"}, {"deflate , gzip"}},
	};
	
	append_header_list_value(headers, "Content-Encoding1", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding1"), "gzip, zstd");
	
	append_header_list_value(headers, "Content-Encoding2", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding2"), "gzip, zstd");
	
	append_header_list_value(headers, "Content-Encoding3", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding3"), "gzip, zstd");
	
	append_header_list_value(headers, "Content-Encoding4", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding4"), "gzip , zstd");
	
	append_header_list_value(headers, "Content-Encoding5", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding5"), "deflate , gzip, zstd");
	
	append_header_list_value(headers, "Content-Encoding6", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Content-Encoding6"), "zstd");
	
	set_header(headers, "Test", "  ");
	append_header_list_value(headers, "Test", "zstd");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Test"), "zstd");
}

BOOST_AUTO_TEST_SUITE_END()
