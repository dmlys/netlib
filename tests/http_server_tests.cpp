#include <ext/net/http/http_server.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/dataset.hpp>

#include "test_files.h"
#include "http_server_tests_utils.hpp"


using namespace ext::net;
using namespace ext::net::http;
using namespace ext::net::http::test_utils;

using boost::unit_test::data::make;

class configurator
{
public:
	using function_type = std::tuple<std::string, unsigned short>(http_server & server);
	
private:
	std::string m_name;
	std::function<function_type> m_configurator;
	
public:
	const auto & name() const noexcept { return m_name; }
	auto operator()(http_server & server) const { return m_configurator(server); }
	
public:
	configurator(std::string name, std::function<function_type> configurator)
		: m_name(std::move(name)), m_configurator(std::move(configurator)) {}
};

inline auto & operator <<(std::ostream & os, const configurator & arg)
{
	return os << arg.name();
}

static std::vector<configurator> configurations = 
{
	{"single", configure},
	{"with_pool", [](auto & server) { return configure_with_pool(server); }},
};


BOOST_AUTO_TEST_SUITE(http_server_tests)

BOOST_DATA_TEST_CASE(simple_tests, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	std::string actual_body;
	int actual_code;
	
	server.start();
	
	server.add_handler("/test", [] { return "test"; });
	std::tie(actual_code, std::ignore, actual_body) = make_get_request(addr, "/test");
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "test");
	
	server.add_handler("/hello-server", [] { return "hello client"; });
	std::tie(actual_code, std::ignore, actual_body) = make_get_request(addr, "/hello-server");
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "hello client");
	
	server.add_handler("/put-test", [&actual_body](const std::string & body) { actual_body = body; return null_body; });
	std::tie(actual_code, std::ignore, std::ignore) = make_put_request(addr, "/put-test", "put-body");
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "put-body");
	
	std::tie(actual_code, std::ignore, std::ignore) = make_put_expect_request(addr, "/put-test", "put-body-with-expect");
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "put-body-with-expect");
	
	server.stop();
}

BOOST_DATA_TEST_CASE(async_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	std::string actual_body;
	int actual_code;
	
	server.start();
	async_request_queue request_queue;
	server.add_handler("/", request_queue.handler());
	
	auto sock = connect_socket(addr);
	write_get_request(sock, addr, "/");
	auto req = request_queue.next_request();
	
	http_response response = make_response(200, "Hello World");
	request_queue.answer(std::move(response));
	
	std::tie(actual_code, std::ignore, actual_body) = parse_response(sock);
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "Hello World");
	
	server.stop();
}

BOOST_DATA_TEST_CASE(request_stream_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	server.start();
	
	http_headers_vector headers;
	std::string actual_body;
	int actual_code;
	
	auto handler = [&actual_body] (std::unique_ptr<std::streambuf> & stream) { actual_body = read_stream(stream.get()); return ""; };
	server.add_handler("put", "/put-stream", handler);
	std::tie(actual_code, std::ignore, std::ignore) = make_put_expect_request(addr, "/put-stream", {"part1", "part2", "part3"});
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "part1part2part3");
	
	server.stop();
}

BOOST_DATA_TEST_CASE(response_stream_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	server.start();
	
	http_headers_vector headers;
	std::string actual_body;
	int actual_code;
	
	auto handler = [] { return std::make_unique<parted_stream>(std::vector<std::string>({"gp1", "part2", "end_part_3"})); };
	server.add_handler("/get-stream", handler);
	std::tie(actual_code, headers, actual_body) = make_get_request(addr, "/get-stream");
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "gp1part2end_part_3");
	BOOST_CHECK_EQUAL(get_header_value(headers, "Transfer-Encoding"), "chunked");
	
	server.stop();
}

BOOST_DATA_TEST_CASE(lingering_request_stream_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	server.start();
	async_request_queue request_queue;
	server.add_handler("/", request_queue.handler(), http_body_type::stream);

	auto sock = connect_socket(addr);
	//sock.timeout(std::chrono::seconds(0));
	
	sock
		<< "PUT / HTTP/1.1\r\n"
		<< "Host: localhost\r\n"
		<< "Expect: 100-continue\r\n"
		<< "Content-Length: 10\r\n"
		<< "Connection: close\r\n"
		<< "\r\n";
	sock << "Hello" /*<< "World"*/;
	sock << std::flush;
	
	auto req = request_queue.next_request();
	auto & body_stream = std::get<std::unique_ptr<std::streambuf>>(req.body);
	
	std::string body;
	body.resize(10);
	
	body_stream->sgetc();
	auto read = body_stream->sgetn(body.data(), body_stream->in_avail());
	BOOST_CHECK_EQUAL(read, 5);
	BOOST_CHECK_EQUAL(body.substr(0, 5), "Hello");
	
	auto fres = ext::async([&body_stream] { return body_stream->sgetc(); });
	std::this_thread::yield();
	
	server.stop();
	
	BOOST_CHECK_THROW(fres.get(), closed_exception);
}

BOOST_DATA_TEST_CASE(lingering_response_stream_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	server.start();
	server.add_handler("/", [] { return std::make_unique<infinite_stream>(); });
	
	auto sock = connect_socket(addr);
	
	sock
		<< "GET / HTTP/1.1\r\n"
		<< "Host: localhost\r\n"
		<< "Connection: close\r\n"
		<< "\r\n";
	sock << std::flush;
	
	server.stop();
}

BOOST_DATA_TEST_CASE(request_async_source_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	async_request_queue request_queue;
	http_headers_vector headers;
	
	server.start();
	server.add_handler("/put-asource", request_queue.handler(), http_body_type::async);
	//auto handler = [] { return std::make_unique<parted_source>(std::vector<std::string>({"gp1", "part2", "end_part_3"})); };
	
	auto sock = connect_socket(addr);
	write_put_expect_request(sock, addr, "/put-asource", {"part1", "part2", "part3"});
	
	auto source_req = request_queue.next_request();
	auto & body_source = std::get<std::unique_ptr<async_http_body_source>>(source_req.body);
	
	auto actual_req_body = read_asource(body_source.get());
	BOOST_CHECK_EQUAL(actual_req_body, "part1part2part3");
	
	http_response response = make_response(200, "OK");
	request_queue.answer(std::move(response));
	
	std::string actual_resp_body;
	int actual_code;
	
	std::tie(actual_code, std::ignore, actual_resp_body) = parse_response(sock);
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_resp_body, "OK");
	
	server.stop();
}

BOOST_DATA_TEST_CASE(response_async_source_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	server.start();
	server.add_handler("/get-asource", [] { return std::make_unique<parted_asource>(std::vector<std::string>{"gp1", "part2", "end_part3"}); });
	
	auto sock = connect_socket(addr);
	write_get_request(sock, addr, "/get-asource");
	
	std::string actual_body;
	int actual_code;
	std::tie(actual_code, std::ignore, actual_body) = parse_response(sock);
	
	BOOST_CHECK_EQUAL(actual_code, 200);
	BOOST_CHECK_EQUAL(actual_body, "gp1part2end_part3");
	
	server.stop();
}

BOOST_DATA_TEST_CASE(body_destruction_test, make(configurations), configurator)
{
	http_server server;
	auto addr = configurator(server);
	
	server.start();
	async_request_queue request_queue;
	server.add_handler("/stream", request_queue.handler(), http_body_type::stream);
	server.add_handler("/async", request_queue.handler(), http_body_type::async);
	
	auto sock1 = connect_socket(addr);
	auto sock2 = connect_socket(addr);
	
	write_put_expect_request(sock1, addr, "/stream", "Hello");
	write_put_expect_request(sock2, addr, "/async", "Hello");
	
	auto stream_req = request_queue.next_request();
	auto & body_stream = std::get<std::unique_ptr<std::streambuf>>(stream_req.body);
	body_stream.reset();
	
	auto async_req = request_queue.next_request();
	auto & body_asource = std::get<std::unique_ptr<async_http_body_source>>(async_req.body);
	body_asource.reset();
	
	server.stop();
}

BOOST_AUTO_TEST_SUITE_END()
