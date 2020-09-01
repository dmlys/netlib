#include "http_server_tests_utils.hpp"

#include <algorithm>
#include <numeric>

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
#if BOOST_OS_LINUX
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
		//static ext::library_logger::stream_logger logger(std::cout, ext::library_logger::Trace);
		//server.set_logger(&logger);
		
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
	
	void write_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, const http_request & request)
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
		
		sock << std::get<std::string>(request.body);
		sock << std::flush;
	}
	
	auto parse_response(ext::net::socket_stream & sock) -> std::tuple<int, http_headers_vector, std::string>
	{
		int code;
		std::string status, name, value, body;
		http_headers_vector headers;
		
		ext::net::http_parser parser;
		parser.parse_status(sock, status);
		
		if (parser.http_code() == 100) // Expect answer, skip it
		{
			parser.parse_trailing(sock);
			parser.reset();
		}
		
		while (parser.parse_header(sock, name, value))
			add_header(headers, name, value);
		
		parser.parse_body(sock, body);
		code = parser.http_code();
		
		return std::make_tuple(code, std::move(headers), std::move(body));
	}
	
	http_response make_response(int code, std::string body)
	{
		http_response response;
		response.http_code = code;
		response.body = std::move(body);
		
		return response;
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
			[](std::size_t & acc, auto & part) { return acc + part.size(); });
		
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
	
	auto make_get_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url)
		-> std::tuple<int, http_headers_vector, std::string>
	{
		auto sock = connect_socket(addr);
		write_get_request(sock, addr, url);
		
		return parse_response(sock);
	}
	
	auto make_put_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body)
		-> std::tuple<int, http_headers_vector, std::string>
	{
		auto sock = connect_socket(addr);
		write_put_request(sock, addr, url, request_body);
	
		return parse_response(sock);
	}
	
	auto make_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body)
		-> std::tuple<int, http_headers_vector, std::string>
	{
		auto sock = connect_socket(addr);
		write_put_expect_request(sock, addr, url, request_body);
		
		return parse_response(sock);
	}
	
	auto make_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::vector<std::string_view> request_body_parts)
		-> std::tuple<int, http_headers_vector, std::string>
	{
		auto sock = connect_socket(addr);
		write_put_expect_request(sock, addr, url, request_body_parts);
	
		return parse_response(sock);
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
	
	auto parted_asource::read_some(std::vector<char> buffer) -> ext::future<chunk_type>
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
}
