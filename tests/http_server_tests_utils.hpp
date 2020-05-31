#pragma once
#include <ext/net/socket_include.hpp>
#include <ext/net/http/http_server.hpp>
#include <ext/library_logger/logger.hpp>

#include <deque>
#include <tuple>
#include <ext/future.hpp>

namespace ext::net::http::test_utils
{
	std::string read_stream(std::streambuf * stream);
	// should not be called from http_server threads(for example directly from handler)
	std::string read_asource(async_http_body_source * source);
	
	void set_nodelay(socket_handle_type handle, int enable);
	auto make_listener() -> ext::net::listener;
	auto configure(http_server & server) -> std::tuple<std::string, unsigned short>;
	auto configure_with_pool(http_server & server, unsigned nthread = 4) -> std::tuple<std::string, unsigned short>;
	
	auto connect_socket(const std::tuple<std::string, unsigned short> & addr) -> ext::net::socket_stream;
	void write_request(const std::tuple<std::string, unsigned short> & addr, const http_request & req);
	auto parse_response(ext::net::socket_stream & sock) -> std::tuple<int, http_headers_vector, std::string>;

	http_response make_response(int code, std::string body);
	
	void write_get_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url);
	void write_put_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body);
	void write_put_expect_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body);
	void write_put_expect_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::vector<std::string_view> request_body_parts);
	
	auto make_get_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url)
		-> std::tuple<int, http_headers_vector, std::string>;
	
	auto make_put_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body)
		-> std::tuple<int, http_headers_vector, std::string>;
	
	auto make_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body)
		-> std::tuple<int, http_headers_vector, std::string>;
	
	auto make_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::vector<std::string_view> request_body_parts)
		-> std::tuple<int, http_headers_vector, std::string>;
	
	
	class parted_stream : public std::streambuf
	{
	private:
		std::vector<std::string> m_parts;
		std::size_t m_cur = 0;
		
	protected:
		virtual int_type underflow() override;
		
	public:
		parted_stream(std::vector<std::string> parts)
		    : m_parts(std::move(parts)) {}
	};
	
	
	class infinite_stream : public std::streambuf
	{
	private:
		std::string m_iter_data = "word ";
		
	protected:
		virtual int_type underflow() override;
		
	public:
		infinite_stream() = default;
	};
	
	
	class parted_asource : public async_http_body_source
	{
	private:
		std::vector<std::string> m_parts;
		std::size_t m_cur = 0;
		
	public:
		virtual ext::future<chunk_type> read_some(std::vector<char> buffer) override;
		
	public:
		parted_asource() = default;
		parted_asource(std::vector<std::string> parts)
		    : m_parts(std::move(parts)) {}
	};
	
	
	
	class async_request_queue
	{
		struct request_item
		{
			ext::promise<http_request> request_promise;
			ext::promise<http_response> response_promise;
		};
		
		std::mutex m_mutex;
		std::condition_variable m_cond;
		std::deque<request_item> m_requests;
		std::size_t m_cur = 0;
		
	public:
		auto next_request() -> http_request;
		auto put_request(http_request request) -> ext::future<http_response>;
		void answer(http_response response);
		
		auto handler();
	};
	
	inline auto async_request_queue::handler()
	{
		return [this](http_request & request) { return put_request(std::move(request)); };
	}
}

