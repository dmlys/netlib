#include <ext/net/http/http_server.hpp>
#include <ext/net/http/zlib_filter.hpp>

#include <ext/stream_filtering.hpp>
#include <ext/stream_filtering/zlib.hpp>
#include <ext/base64.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/dataset.hpp>

#include "test_files.h"
#include "http_server_tests_utils.hpp"


using namespace ext::net;
using namespace ext::net::http;
using namespace ext::net::http::test_utils;

using boost::unit_test::data::make;

#ifdef EXT_ENABLE_CPPZLIB
static std::string gzip(std::string_view data)
{
	ext::stream_filtering::zlib_deflate_filter zipper;
	std::array filters = { &zipper };
	
	std::string result;
	ext::stream_filtering::filter_memory(filters, data, result);
	return result;
}

static std::string ungzip(std::string_view data)
{
	ext::stream_filtering::zlib_inflate_filter unzipper;
	std::array filters = { &unzipper };
	
	std::string result;
	ext::stream_filtering::filter_memory(filters, data, result);
	return result;
}

static http_request make_gzip_request(std::string method, std::string url, std::string_view body)
{
	http_request req;
	req.method = std::move(method);
	req.url = std::move(url);
	req.body = gzip(body);
	
	set_header(req.headers, "Content-Length", std::to_string(*size(req.body)));
	set_header(req.headers, "Content-Encoding", "gzip");
	set_header(req.headers, "Accept-Encoding", "gzip");
	
	return req;
}

#endif // EXT_ENABLE_CPPZLIB

BOOST_AUTO_TEST_SUITE(http_server_tests)

#ifdef EXT_ENABLE_CPPZLIB
BOOST_DATA_TEST_CASE(zlib_filter_simple_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	server.start();
	server.add_filter(ext::make_intrusive<ext::net::http::zlib_filter>());
	
	async_request_queue request_queue;
	server.add_handler("/echo", request_queue.handler(), http_body_type::string);
	
	auto sock = connect_socket(addr);
	auto httpreq = make_gzip_request("PUT", "/echo", "test");
	write_request(sock, addr, httpreq);
	
	auto request = request_queue.next_request();
	auto reqbody = std::get<std::string>(request.body);
	BOOST_CHECK_EQUAL(reqbody, "test");
	
	request_queue.answer(make_response(200, "test"));
	
	auto response = receive_response(sock);
	BOOST_CHECK_EQUAL(response.http_code, 200);
	BOOST_REQUIRE_EQUAL(get_header_value(response.headers, "Content-Encoding"), "gzip");
	
	auto respbody = ungzip(std::get<std::string>(response.body));
	BOOST_CHECK_EQUAL(respbody, "test");
	
	server.stop();
}

BOOST_DATA_TEST_CASE(zlib_filter_simple_huge_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	std::string reqbody;
	reqbody.resize(1024 * 1024, '1'); // one meg of '1'
	
	server.start();
	server.add_filter(ext::make_intrusive<ext::net::http::zlib_filter>());
	
	server.add_handler("/echo", [](std::string & str) { return str; });
	
	auto sock = connect_socket(addr);
	auto httpreq = make_gzip_request("PUT", "/echo", reqbody);
	write_request(sock, addr, httpreq);
	
	auto httpresp = receive_response(sock);
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
	BOOST_REQUIRE_EQUAL(get_header_value(httpresp.headers, "Content-Encoding"), "gzip");
	
	auto respbody = ungzip(std::get<std::string>(httpresp.body));
	BOOST_CHECK(respbody == reqbody);
}
#endif // EXT_ENABLE_CPPZLIB

BOOST_DATA_TEST_CASE(base64_filter_simple_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	std::string reqbody;
	reqbody.resize(1024 * 1024, '1'); // one meg of '1'
	
	server.start();
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	
	server.add_handler("/echo", [](std::string & str) { return str; });
	
	auto httpresp = send_put_request(addr, "/echo", ext::encode_base64(reqbody));
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
	
	auto respbody = std::get<std::string>(httpresp.body);
	respbody = ext::decode_base64(respbody);
	
	BOOST_CHECK(respbody == reqbody);
}

BOOST_DATA_TEST_CASE(base64_filter_stream_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	std::string testbody, reqbody;
	testbody.resize(1024 * 1024, '1');
	
	server.start();
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	
	ext::promise<std::string> reqbody_promise;
	auto handler = [&reqbody_promise] (std::unique_ptr<std::streambuf> & stream)
	{
		auto body = read_stream(stream.get());
		reqbody_promise.set_value(body);
		return std::make_unique<std::stringbuf>(body);
	};
	
	server.add_handler("/test", handler);
	
	auto sock = connect_socket(addr);
	auto httpresp = send_put_request(addr, "/test", ext::encode_base64(testbody));
	
	reqbody = reqbody_promise.get_future().get();
	BOOST_CHECK(reqbody == testbody);
	
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
	
	auto respbody = std::get<std::string>(httpresp.body);
	respbody = ext::decode_base64(respbody);
	BOOST_CHECK(respbody == testbody);
}

BOOST_DATA_TEST_CASE(base64_filter_async_request_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	async_request_queue request_queue;
	std::string testbody, reqbody;
	testbody.resize(1024 * 1024, '1');
	
	server.start();
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	
	server.add_handler("/test", request_queue.handler(), http_body_type::async);
		
	auto sock = connect_socket(addr);
	auto httpreq = make_request("PUT", "/test", testbody);
	httpreq.body = ext::encode_base64(std::get<std::string>(httpreq.body));
	set_header(httpreq.headers, "Content-Length", std::to_string(*size(httpreq.body)));
	write_headers(sock, addr, httpreq);
	
	auto source_req = request_queue.next_request();
	auto & body_source = std::get<std::unique_ptr<async_http_body_source>>(source_req.body);
		
	auto f = ext::async(ext::launch::async, [&body_source]
	{
		std::vector<char> buffer;
		std::string reqbody;
		for (;;)
		{
			auto f = body_source->read_some(std::move(buffer));
			auto result = f.get();
			if (not result) break;
			
			buffer = std::move(*result);
			reqbody.append(buffer.data(), buffer.size());	
		}
		
		return reqbody;
	});
	
	// TODO: insert delay here for would block
	auto & input_body = std::get<std::string>(httpreq.body);
	sock.write(input_body.data(), input_body.size());
	
	reqbody = f.get();
	
	BOOST_CHECK(reqbody == testbody);
	request_queue.answer(make_response(200, ""));
	
	auto httpresp = receive_response(sock);
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
}

BOOST_DATA_TEST_CASE(base64_filter_async_response_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	async_request_queue request_queue;
	std::string testbody, respbody;
	testbody.resize(1024 * 1024, '1');
	
	server.start();
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	
	server.add_handler("/test", request_queue.handler(), http_body_type::null);
	
	auto sock = connect_socket(addr);
	write_get_request(sock, addr, "/test");
	
	std::vector<std::string> async_parts;
	for (unsigned i = 0; i < 1024; i++)
		async_parts.push_back(std::string(testbody.substr(i * 1024, 1024)));
	
	http_response httpresp;
	httpresp.http_code = 200;
	httpresp.body = std::make_unique<parted_asource>(std::move(async_parts));
	
	request_queue.answer(std::move(httpresp));
	
	httpresp = receive_response(sock);
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
	
	respbody = std::get<std::string>(httpresp.body);
	respbody = ext::decode_base64(respbody);
	BOOST_CHECK(testbody == respbody);
}


#ifdef EXT_ENABLE_CPPZLIB

BOOST_DATA_TEST_CASE(complex_filter_stream_request_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	std::string testbody, reqbody;
	testbody.resize(1024 * 1024, '1');
	
	server.start();
	server.add_filter(ext::make_intrusive<ext::net::http::zlib_filter>());
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	
	ext::promise<std::string> reqbody_promise;
	auto handler = [&reqbody_promise] (std::unique_ptr<std::streambuf> & stream)
	{
		auto body = read_stream(stream.get());
		reqbody_promise.set_value(body);
		return "";
	};
	
	server.add_handler("/test", handler);
	
	auto sock = connect_socket(addr);
	auto httpreq = make_gzip_request("PUT", "/test", testbody);
	httpreq.body = ext::encode_base64(std::get<std::string>(httpreq.body));
	set_header(httpreq.headers, "Content-Length", std::to_string(*size(httpreq.body)));
	write_request(sock, addr, httpreq);
	
	reqbody = reqbody_promise.get_future().get();
	BOOST_CHECK(reqbody == testbody);
	
	auto httpresp = receive_response(sock);
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
}

BOOST_DATA_TEST_CASE(complex_filter_stream_response_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	std::string testbody, respbody;
	testbody.resize(1024 * 1024, '1');
	
	server.start();
	server.add_filter(ext::make_intrusive<ext::net::http::zlib_filter>());
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	
	auto handler = [&testbody] { return std::make_unique<std::stringbuf>(testbody); };
	server.add_handler("/test", handler);
	
	auto sock = connect_socket(addr);
	http_request httpreq = make_request("GET", "/test", {});
	set_header(httpreq.headers, "Accept-Encoding", "gzip");
	write_request(sock, addr, httpreq);
	
	auto httpresp = receive_response(sock);
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
	BOOST_CHECK_EQUAL(get_header_value(httpresp.headers, "Content-Encoding"), "gzip");
	
	respbody = std::get<std::string>(httpresp.body);
	respbody = ext::decode_base64(respbody);
	respbody = ungzip(respbody);
	BOOST_CHECK(testbody == respbody);
	
}

BOOST_DATA_TEST_CASE(complex_filter_async_request_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	async_request_queue request_queue;
	std::string testbody, reqbody;
	testbody.resize(1024 * 1024, '1');
	
	server.start();
	server.add_filter(ext::make_intrusive<ext::net::http::zlib_filter>());
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	server.add_handler("/test", request_queue.handler(), http_body_type::async);
	
	auto sock = connect_socket(addr);
	auto httpreq = make_gzip_request("PUT", "/test", testbody);
	httpreq.body = ext::encode_base64(std::get<std::string>(httpreq.body));
	set_header(httpreq.headers, "Content-Length", std::to_string(*size(httpreq.body)));
	write_request(sock, addr, httpreq);
	
	auto source_req = request_queue.next_request();
	auto & body_source = std::get<std::unique_ptr<async_http_body_source>>(source_req.body);
	reqbody = read_asource(body_source.get());
	
	BOOST_CHECK(reqbody == testbody);
	request_queue.answer(make_response(200, ""));
	
	auto httpresp = receive_response(sock);
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
}

BOOST_DATA_TEST_CASE(complex_filter_async_response_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	async_request_queue request_queue;
	std::string testbody, respbody;
	testbody.resize(1024 * 1024, '1');
	
	server.start();
	server.add_filter(ext::make_intrusive<ext::net::http::zlib_filter>());
	server.add_filter(ext::make_intrusive<dumb_base64_filter>());
	
	server.add_handler("/test", request_queue.handler(), http_body_type::null);
	
	auto sock = connect_socket(addr);
	http_request httpreq = make_request("GET", "/test", {});
	set_header(httpreq.headers, "Accept-Encoding", "gzip");
	write_request(sock, addr, httpreq);
	
	std::vector<std::string> async_parts;
	for (unsigned i = 0; i < 1024; i++)
		async_parts.push_back(std::string(testbody.substr(i * 1024, 1024)));
	
	http_response httpresp;
	httpresp.http_code = 200;
	httpresp.body = std::make_unique<parted_asource>(std::move(async_parts));
	
	request_queue.answer(std::move(httpresp));
	
	httpresp = receive_response(sock);
	BOOST_CHECK_EQUAL(httpresp.http_code, 200);
	BOOST_CHECK_EQUAL(get_header_value(httpresp.headers, "Content-Encoding"), "gzip");
	
	respbody = std::get<std::string>(httpresp.body);
	respbody = ext::decode_base64(respbody);
	respbody = ungzip(respbody);
	BOOST_CHECK(testbody == respbody);
}

#endif // EXT_ENABLE_CPPZLIB

BOOST_AUTO_TEST_SUITE_END()
