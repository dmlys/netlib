#pragma once
#include <ext/net/socket_include.hpp>
#include <ext/net/socket_stream.hpp>
#include <ext/net/http/http_server.hpp>
#include <ext/log/logger.hpp>

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
	void write_headers(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, const http_request & req);
	void write_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, const http_request & req);
	auto receive_response(ext::net::socket_stream & sock) -> http_response;

	http_response make_response(int code, std::string body);
	http_request  make_request(std::string method, std::string url, std::string body, http_headers_vector headers = {});
	
	void write_get_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url);
	void write_put_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body);
	void write_put_expect_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body);
	void write_put_expect_request(ext::net::socket_stream & sock, const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::vector<std::string_view> request_body_parts);
	
	auto send_get_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url) -> http_response;
	auto send_put_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body) -> http_response;
	auto send_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::string_view request_body) -> http_response;
	auto send_put_expect_request(const std::tuple<std::string, unsigned short> & addr, std::string_view url, std::vector<std::string_view> request_body_parts) -> http_response;
	
	class dumb_base64_filter : public http_prefilter, public http_postfilter
	{
	public:
		virtual unsigned preorder() const noexcept override { return 0; }
		virtual unsigned postorder() const noexcept override { return UINT_MAX; }
		
		virtual void postfilter(http_server_control & control) const override;
		virtual void prefilter(http_server_control & control) const override;
	};
	
	
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
		virtual ext::future<chunk_type> read_some(std::vector<char> buffer, std::size_t size = 0) override;
		
	public:
		parted_asource() = default;
		parted_asource(std::vector<std::string> parts)
		    : m_parts(std::move(parts)) {}
	};
	
	
	class infinite_asource : public async_http_body_source
	{
	private:
		std::string m_iter_data = "word ";
	
	public:
		virtual ext::future<chunk_type> read_some(std::vector<char> buffer, std::size_t size = 0) override;
		
	public:
		infinite_asource() = default;		
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
	
	extern std::vector<configurator> configurations;
	//{
	//	{"single", configure},
	//	{"with_pool", [](auto & server) { return configure_with_pool(server); }},
	//};
}


struct unwrap_tag_type {} constexpr unwrap_tag;

inline std::tuple<int, ext::net::http::http_headers_vector, std::string> operator <<(unwrap_tag_type, ext::net::http::http_response && resp)
{
	return std::make_tuple(resp.http_code, std::move(resp.headers), std::get<std::string>(std::move(resp.body)));
}
