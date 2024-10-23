#include "http_server_tests_utils.hpp"
#include "test_files.h"

#include <algorithm>
#include <numeric>
#include <iostream>

#include <ext/stream_filtering/basexx.hpp>

namespace ext::net::http::test_utils
{
	std::string read_stream(std::streambuf * stream)
	{
		std::string result;
		for (;;)
		{
			char buffer[1024];
			auto read = stream->sgetn(buffer, 1024);
			if (read == 0) break;
			
			result.append(buffer, read);
		}
		
		return result;
	}
	
	std::string read_asource(async_http_body_source * source)
	{
		std::string result;
		std::vector<char> buffer;
		for (;;)
		{
			auto fres = source->read_some(std::move(buffer));
			auto res = fres.get();
			if (not res) return result;
			
			buffer = std::move(*res);
			result.append(buffer.data(), buffer.size());
		}
	}
	
	void set_nodelay(socket_handle_type handle, int enable)
	{
		int res = ::setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&enable), sizeof(enable));
		if (res != 0) throw_last_socket_error("setsockopt IPPROTO_TCP/TCP_NODELAY failed");
	}
	
	auto make_listener() -> ext::net::listener
	{
		// prefer INADDR_LOOPBACK over IPADDR_ANY
#if 0 //BOOST_OS_LINUX
		// According to man 7 ip:
		// When listen(2) is called on an unbound socket,
		// the socket is automatically bound to a random free port with the local address set to INADDR_ANY.
		// So we create socket and call listen on it without calling bind
		
		auto listener_socket = ::socket(AF_INET, SOCK_STREAM, 0);
		if (listener_socket == ext::net::invalid_socket) ext::net::throw_last_socket_error("::socket call failed");
		
		ext::net::listener listener(handle_arg, listener_socket);
		listener.listen(1);
		
		return listener;
#else
		auto addrinfo = loopback_addr(AF_UNSPEC, SOCK_STREAM);
		ext::net::listener listener;
		listener.bind(addrinfo->ai_addr, addrinfo->ai_addrlen, addrinfo->ai_socktype, addrinfo->ai_protocol);
		listener.listen(1);
		
		return listener;
#endif
	}
	
	auto configure(http_server & server) -> std::tuple<std::string, unsigned short>
	{
		if (LogLevel < ext::log::Disabled)
		{
			static ext::log::ostream_logger logger(std::cout, LogLevel);
			server.set_logger(&logger);
		}
		
		auto listener = make_listener();
		auto addr = listener.sock_name();
		
		server.add_listener(std::move(listener));
		return addr;
	}
	
	auto configure_with_pool(http_server & server, unsigned nthreads) -> std::tuple<std::string, unsigned short>
	{
		auto addr = configure(server);
		auto pool = std::make_shared<ext::thread_pool>(nthreads);
		server.set_thread_pool(std::move(pool));
		
		return addr;
	}
	
	auto connect_socket(const std::tuple<std::string, unsigned short> & addr) -> ext::net::socket_stream
	{
		const std::string & host = std::get<0>(addr);
		const unsigned short port = std::get<1>(addr);
		
		ext::net::socket_stream sock;
		sock.timeout(std::chrono::steady_clock::duration::max());
		sock.connect(host, port);
		sock.rdbuf()->throw_errors(true);
		
		return sock;
	}
	
	void write_headers(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, const http_request & request)
	{
		const std::string & host = std::get<0>(addr);
		
		std::string_view connection_action;
		switch (request.conn_action)
		{
			case connection_action_type::def:
			case connection_action_type::keep_alive:
				connection_action = "Keep-Alive";
				break;
				
			case connection_action_type::close:
				connection_action = "close";
				break;
				
			default:
				EXT_UNREACHABLE();
		}
		
		sock
			<< request.method << " " << request.url << " HTTP/1.1\r\n"
			<< "Host: " << host << "\r\n";
		
		for (const auto & [name, value] : request.headers)
			sock << name << ": " << value << "\r\n";
		
		sock << "Connection: " << connection_action << "\r\n"
			 << "\r\n";
		
		sock << std::flush;
	}
	
	void write_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, const http_request & request)
	{
		write_headers(sock, addr, request);
		sock << std::get<std::string>(request.body);
		sock << std::flush;
	}
	
	auto receive_response(ext::net::socket_stream & sock) -> http_response
	{
		http_response resp;
		std::string name, value, body;
		ext::net::http::http_parser parser;
		parser.parse_status(sock, resp.status);
		
		if (parser.http_code() == 100) // Expect answer, skip it
		{
			parser.parse_trailing(sock);
			parser.reset();
		}
		
		while (parser.parse_header(sock, name, value))
			add_header(resp.headers, name, value);
		
		parser.parse_body(sock, body);
		resp.body = std::move(body);
		resp.http_code = parser.http_code();
		
		return resp;
	}
	
	http_response make_response(int code, std::string body)
	{
		http_response response;
		response.http_code = code;
		response.body = std::move(body);
		
		return response;
	}
	
	http_request make_request(std::string method, std::string url, std::string body, http_headers_vector headers)
	{
		http_request request;
		request.method = std::move(method);
		request.url = std::move(url);
		request.body = std::move(body);
		request.headers = std::move(headers);
		
		return request;
	}
	
	void write_get_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url)
	{
		const std::string & host = std::get<0>(addr);
		
		sock
			<< "GET " << url << " HTTP/1.1\r\n"
			<< "Host: " << host << "\r\n"
			<< "Connection: close\r\n"
			<< "\r\n";
		
		sock << std::flush;
	}
	
	void write_put_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body)
	{
		const std::string & host = std::get<0>(addr);
		
		sock
			<< "PUT " << url << " HTTP/1.1\r\n"
			<< "Host: " << host << "\r\n"
		    << "Content-Length: " << std::to_string(request_body.size()) << "\r\n"
			<< "Connection: close\r\n"
			<< "\r\n"
			<< request_body;
		
		sock << std::flush;
	}
	
	void write_put_expect_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body)
	{
		const std::string & host = std::get<0>(addr);
		
		sock
			<< "PUT " << url << " HTTP/1.1\r\n"
			<< "Host: " << host << "\r\n"
			<< "Content-Length: " << std::to_string(request_body.size()) << "\r\n"
		    << "Expect: 100-continue\r\n"
			<< "Connection: close\r\n"
			<< "\r\n"
			<< request_body;
		
		sock << std::flush;
	}
	
	void write_put_expect_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::vector<std::string_view> request_body_parts)
	{
		const std::string & host = std::get<0>(addr);
		
		std::size_t len = 0;
		len = std::accumulate(request_body_parts.begin(), request_body_parts.end(), len,
			[](std::size_t acc, auto & part) { return acc + part.size(); });
		
		sock
			<< "PUT " << url << " HTTP/1.1\r\n"
		    << "Host: " << host << "\r\n"
		    << "Connection: close\r\n"
		    << "Content-Length: " << std::to_string(len) << "\r\n"
		    << "Expect: 100-continue\r\n"
		    << "\r\n";
		
		set_nodelay(sock.handle(), 1);
		for (auto & part : request_body_parts)
			sock << part << std::flush;
		
		set_nodelay(sock.handle(), 0);
	}
	
	auto send_get_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url) -> http_response
	{
		auto sock = connect_socket(addr);
		write_get_request(sock, addr, url);
		
		return receive_response(sock);
	}
	
	auto send_put_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body) -> http_response
	{
		auto sock = connect_socket(addr);
		write_put_request(sock, addr, url, request_body);
	
		return receive_response(sock);
	}
	
	auto send_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body) -> http_response
	{
		auto sock = connect_socket(addr);
		write_put_expect_request(sock, addr, url, request_body);
		
		return receive_response(sock);
	}
	
	auto send_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::vector<std::string_view> request_body_parts) -> http_response
	{
		auto sock = connect_socket(addr);
		write_put_expect_request(sock, addr, url, request_body_parts);
	
		return receive_response(sock);
	}
	
	void dumb_base64_filter::prefilter(http_server_control & control) const
	{
		control.request_filter_append(std::make_unique<ext::stream_filtering::base64_decode_filter>());
	}
	
	void dumb_base64_filter::postfilter(http_server_control & control) const
	{
		control.response_filter_append(std::make_unique<ext::stream_filtering::base64_encode_filter>());
	}
	
	auto parted_stream::underflow() -> int_type
	{
		if (m_cur >= m_parts.size())
			return traits_type::eof();
		
		auto & part = m_parts[m_cur++];
		auto * first = part.data();
		auto * last  = first + part.size();
		setg(first, first, last);
		
		return traits_type::to_int_type(*first);
	}

	auto infinite_stream::underflow() -> int_type
	{
		auto * first = m_iter_data.data();
		auto * last  = first + m_iter_data.size();
		setg(first, first, last);
	
		std::this_thread::yield();
		return traits_type::to_int_type(*first);
	}
	
	auto parted_asource::read_some(std::vector<char> buffer, std::size_t size) -> ext::future<chunk_type>
	{
		auto func = [this, buffer = std::move(buffer)]() mutable -> chunk_type
		{
			std::this_thread::yield();
			if (m_cur >= m_parts.size())
				return std::nullopt;
				
			auto & part = m_parts[m_cur++];
			buffer.assign(part.data(), part.data() + part.size());
			return buffer;
		};
		
		return ext::async(ext::launch::async, std::move(func));
	}
	
	auto infinite_asource::read_some(std::vector<char> buffer, std::size_t size) -> ext::future<chunk_type>
	{
		auto func = [this, buffer = std::move(buffer)]() mutable -> chunk_type
		{
			std::this_thread::yield();
			buffer.assign(m_iter_data.begin(), m_iter_data.end());
			return buffer;
		};
		
		return ext::async(ext::launch::async, std::move(func));
	}
	
	auto async_request_queue::next_request() -> http_request
	{
		std::unique_lock lk(m_mutex);
		m_cond.wait(lk, [this] { return m_cur < m_requests.size(); });
		
		auto & item = m_requests[m_cur++];
		auto f = item.request_promise.get_future();
		
		lk.unlock();
		m_cond.notify_one();
		
		return f.get();
	}
	
	auto async_request_queue::put_request(http_request request) -> ext::future<http_response>
	{
		std::unique_lock lk(m_mutex);
		
		m_requests.emplace_back();
		auto & item = m_requests.back();
		
		item.request_promise.set_value(std::move(request));
		auto f = item.response_promise.get_future();
		
		lk.unlock();
		m_cond.notify_one();
		
		return f;
	}
	
	void async_request_queue::answer(http_response response)
	{
		std::unique_lock lk(m_mutex);
		m_cond.wait(lk, [this] { return not m_requests.empty(); });
		
		auto promise = std::move(m_requests.front().response_promise);
		m_requests.pop_front();
		m_cur -= 1;
		lk.unlock();
		
		promise.set_value(std::move(response));
	}
	
	std::vector<configurator> configurations = 
	{
		{"single", configure},
		{"with_pool", [](auto & server) { return configure_with_pool(server); }},
	};
}
