#include <ext/net/http/http_types.hpp>
#include <boost/test/unit_test.hpp>
#include <sstream>

namespace ext::net::http
{
	static std::ostream & operator <<(std::ostream & os, ext::net::http::connection_action_type a)
	{
		return os << static_cast<std::underlying_type_t<decltype(a)>>(a);
	}
}


static void check_headers_equal(const ext::net::http::http_headers_vector & hdr1, const ext::net::http::http_headers_vector & hdr2)
{
	BOOST_CHECK_EQUAL(hdr1.size(), hdr2.size());
	for (unsigned u = 0; u < hdr1.size(); ++u)
	{
		const auto & [name1, val1] = hdr1[u];
		const auto & [name2, val2] = hdr2[u];
		
		BOOST_CHECK_EQUAL(name1, name2);
		BOOST_CHECK_EQUAL(val1,  val2);
	}
}

static void check_request_meta_equal(const ext::net::http::http_request & req1, const ext::net::http::http_request & req2)
{
	BOOST_CHECK_EQUAL(req1.http_version, req2.http_version);
	BOOST_CHECK_EQUAL(req1.method      , req2.method      );
	BOOST_CHECK_EQUAL(req1.url         , req2.url         );
	BOOST_CHECK_EQUAL(req1.conn_action , req2.conn_action );
	
	check_headers_equal(req1.headers, req2.headers);
}

static void check_response_meta_equal(const ext::net::http::http_response & resp1, const ext::net::http::http_response & resp2)
{
	BOOST_CHECK_EQUAL(resp1.http_version, resp2.http_version);
	BOOST_CHECK_EQUAL(resp1.http_code   , resp2.http_code   );
	BOOST_CHECK_EQUAL(resp1.status      , resp2.status      );
	BOOST_CHECK_EQUAL(resp1.conn_action , resp2.conn_action );
	
	check_headers_equal(resp1.headers, resp2.headers);
}

static ext::net::http_request http_request_temlpate()
{
	using namespace ext::net::http;
	http_request req;
	req.http_version = 12;
	req.method = "POST";
	req.url = "/test";
	set_header(req.headers, "test-header", "test-val");
	set_header(req.headers, "connection", "keep-alive");
	
	req.conn_action = connection_action_type::keep_alive;
	return req;
}

static ext::net::http_response http_response_temlpate()
{
	using namespace ext::net::http;
	http_response resp;
	resp.http_version = 12;
	resp.http_code = 555;
	resp.status = "555 status";
	set_header(resp.headers, "test-header", "test-val");
	set_header(resp.headers, "connection", "keep-alive");
	
	resp.conn_action = connection_action_type::keep_alive;
	return resp;
}

BOOST_AUTO_TEST_SUITE(http_body_copy_tests)

BOOST_AUTO_TEST_CASE(http_request_copy_test)
{
	using namespace ext::net::http;
	
	std::string_view strval = "test-vector-body";
	std::vector<char> vectval(strval.begin(), strval.end());
	
	http_request req_template, req1, req2;
	req_template = http_request_temlpate();

	// copy_mv
	req1 = copy_meta(req_template);
	req1.body = std::string("test-body");
	
	req2 = copy_mv(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::string>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::string>(req2.body));
	BOOST_CHECK_EQUAL(std::get<std::string>(req1.body), "");
	BOOST_CHECK_EQUAL(std::get<std::string>(req2.body), "test-body");
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
		
	req1 = copy_meta(req_template);
	req1.body = vectval;
	
	req2 = copy_mv(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(req2.body));
	BOOST_CHECK(std::get<std::vector<char>>(req1.body).empty());
	BOOST_CHECK(std::get<std::vector<char>>(req2.body) == vectval);
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
		
	req1 = copy_meta(req_template);
	req1.body = std::make_unique<std::stringbuf>("test-ostream-str");
	
	req2 = copy_mv(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(req2.body));
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(req1.body) == nullptr);
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(req2.body) != nullptr);
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
	
	
	// copy_cp
	req1 = copy_meta(req_template);
	req1.body = std::string("test-body");
	
	req2 = copy_cp(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::string>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::string>(req2.body));
	BOOST_CHECK_EQUAL(std::get<std::string>(req1.body), "test-body");
	BOOST_CHECK_EQUAL(std::get<std::string>(req2.body), "test-body");
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
		
	req1 = copy_meta(req_template);
	req1.body = vectval;
	
	req2 = copy_cp(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(req2.body));
	BOOST_CHECK(std::get<std::vector<char>>(req1.body) == vectval);
	BOOST_CHECK(std::get<std::vector<char>>(req2.body) == vectval);
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
		
	req1 = copy_meta(req_template);
	req1.body = std::make_unique<std::stringbuf>("test-ostream-str");
	
	req2 = copy_cp(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(req2.body));
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(req1.body) == nullptr);
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(req2.body) != nullptr);
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
	
	
	// copy_chk
	req1 = copy_meta(req_template);
	req1.body = std::string("test-body");
	
	req2 = copy_chk(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::string>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::string>(req2.body));
	BOOST_CHECK_EQUAL(std::get<std::string>(req1.body), "test-body");
	BOOST_CHECK_EQUAL(std::get<std::string>(req2.body), "test-body");
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
		
	req1 = copy_meta(req_template);
	req1.body = vectval;
	
	req2 = copy_chk(req1);
	check_request_meta_equal(req1, req2);
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(req1.body));
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(req2.body));
	BOOST_CHECK(std::get<std::vector<char>>(req1.body) == vectval);
	BOOST_CHECK(std::get<std::vector<char>>(req2.body) == vectval);
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
		
	req1 = copy_meta(req_template);
	req1.body = std::make_unique<std::stringbuf>("test-ostream-str");
	
	using namespace std::literals;
	BOOST_CHECK_EXCEPTION(
		copy_chk(req1), std::runtime_error,
		[](auto & ex) { return ex.what() == "Can't copy from http_body:std::streambuf"sv; }
	);
	
	clear(req1); clear(req2);
	BOOST_CHECK(req1.url.empty() and req1.headers.empty());
	BOOST_CHECK(req2.url.empty() and req2.headers.empty());
}

BOOST_AUTO_TEST_CASE(http_response_copy_test)
{
	using namespace ext::net::http;
	
	std::string_view strval = "test-vector-body";
	std::vector<char> vectval(strval.begin(), strval.end());
	
	http_response resp_template, resp1, resp2;
	resp_template = http_response_temlpate();

	// copy_mv
	resp1 = copy_meta(resp_template);
	resp1.body = std::string("test-body");
	
	resp2 = copy_mv(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::string>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::string>(resp2.body));
	BOOST_CHECK_EQUAL(std::get<std::string>(resp1.body), "");
	BOOST_CHECK_EQUAL(std::get<std::string>(resp2.body), "test-body");
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
		
	resp1 = copy_meta(resp_template);
	resp1.body = vectval;
	
	resp2 = copy_mv(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(resp2.body));
	BOOST_CHECK(std::get<std::vector<char>>(resp1.body).empty());
	BOOST_CHECK(std::get<std::vector<char>>(resp2.body) == vectval);
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
		
	resp1 = copy_meta(resp_template);
	resp1.body = std::make_unique<std::stringbuf>("test-ostream-str");
	
	resp2 = copy_mv(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(resp2.body));
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(resp1.body) == nullptr);
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(resp2.body) != nullptr);
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
	
	
	// copy_cp
	resp1 = copy_meta(resp_template);
	resp1.body = std::string("test-body");
	
	resp2 = copy_cp(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::string>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::string>(resp2.body));
	BOOST_CHECK_EQUAL(std::get<std::string>(resp1.body), "test-body");
	BOOST_CHECK_EQUAL(std::get<std::string>(resp2.body), "test-body");
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
		
	resp1 = copy_meta(resp_template);
	resp1.body = vectval;
	
	resp2 = copy_cp(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(resp2.body));
	BOOST_CHECK(std::get<std::vector<char>>(resp1.body) == vectval);
	BOOST_CHECK(std::get<std::vector<char>>(resp2.body) == vectval);
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
		
	resp1 = copy_meta(resp_template);
	resp1.body = std::make_unique<std::stringbuf>("test-ostream-str");
	
	resp2 = copy_cp(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::unique_ptr<std::streambuf>>(resp2.body));
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(resp1.body) == nullptr);
	BOOST_CHECK(std::get<std::unique_ptr<std::streambuf>>(resp2.body) != nullptr);
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
	
	
	// copy_chk
	resp1 = copy_meta(resp_template);
	resp1.body = std::string("test-body");
	
	resp2 = copy_chk(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::string>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::string>(resp2.body));
	BOOST_CHECK_EQUAL(std::get<std::string>(resp1.body), "test-body");
	BOOST_CHECK_EQUAL(std::get<std::string>(resp2.body), "test-body");
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
		
	resp1 = copy_meta(resp_template);
	resp1.body = vectval;
	
	resp2 = copy_chk(resp1);
	check_response_meta_equal(resp1, resp2);
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(resp1.body));
	BOOST_CHECK(std::holds_alternative<std::vector<char>>(resp2.body));
	BOOST_CHECK(std::get<std::vector<char>>(resp1.body) == vectval);
	BOOST_CHECK(std::get<std::vector<char>>(resp2.body) == vectval);
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
		
	resp1 = copy_meta(resp_template);
	resp1.body = std::make_unique<std::stringbuf>("test-ostream-str");
	
	using namespace std::literals;
	BOOST_CHECK_EXCEPTION(
		copy_chk(resp1), std::runtime_error,
		[](auto & ex) { return ex.what() == "Can't copy from http_body:std::streambuf"sv; }
	);
	
	clear(resp1); clear(resp2);
	BOOST_CHECK(resp1.status.empty() and resp1.headers.empty());
	BOOST_CHECK(resp2.status.empty() and resp2.headers.empty());
}


BOOST_AUTO_TEST_SUITE_END()
