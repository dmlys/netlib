#include <ext/net/socket_queue.hpp>
#include <ext/net/socket_include.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/dataset.hpp>

#include "test_files.h"


BOOST_AUTO_TEST_SUITE(socket_queue_tests)

BOOST_AUTO_TEST_CASE(socket_queue_basic_test)
{
	auto addr_info = ext::net::loopback_addr();
	ext::net::listener listener;
	listener.bind(addr_info->ai_addr, addr_info->ai_addrlen, addr_info->ai_socktype);
	listener.listen(10);
	
	sockaddr_storage addrstore;
	socklen_t addrlen = sizeof(addrstore);
	auto * addr = reinterpret_cast<sockaddr *>(&addrstore);
	listener.getsockname(addr, &addrlen);
	
	ext::net::socket_queue sock_queue;
	//ext::log::ostream_logger logger(std::cout, ext::log::Trace);
	//sock_queue.set_logger(&logger);
	
	sock_queue.add_listener(listener.handle());
	
	int res;
	ext::net::socket_uhandle ss1, ss2, sr3;
	socket_handle_type sres;
	
	std::error_code errc;
	ext::net::socket_queue::wait_status wstat;
	
	ss1.reset( ::socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol) );
	if (ss1 == ext::net::invalid_socket) ext::net::throw_last_socket_error("failed to create socket");
	ss2.reset( ::socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol) );
	if (ss2 == ext::net::invalid_socket) ext::net::throw_last_socket_error("failed to create socket");
	
	res = ::connect(ss1.get(), addr, addrlen);
	if (res) ext::net::throw_last_socket_error("failed to connect socket");
	res = ::connect(ss2.get(), addr, addrlen);
	if (res) ext::net::throw_last_socket_error("failed to connect socket");
	
	ext::net::setsock_nonblocking(ss1.get());
	ext::net::setsock_nonblocking(ss2.get());
	
	std::string str = "Hello world";
	res = ::send(ss2.get(), str.data(), str.size(), 0);
	if (res <= 0) ext::net::throw_last_socket_error("failed to send to socket");
	
	std::tie(wstat, sres, errc) = sock_queue.take();
	sr3.reset(sres);
	BOOST_REQUIRE(wstat == ext::net::socket_queue::ready);
	BOOST_REQUIRE(not errc);
	
	std::string data;
	data.resize(str.size());
	res = ::recv(sres, data.data(), data.size(), 0);
	if (res <= 0) ext::net::throw_last_socket_error("failed to receive socket");
	
	BOOST_CHECK_EQUAL(data, str);
}

BOOST_AUTO_TEST_SUITE_END()
