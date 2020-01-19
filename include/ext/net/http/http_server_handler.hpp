#pragma once
#include <memory>
#include <string>
#include <vector>
#include <variant>
#include <functional>

#include <ext/future.hpp>
#include <ext/net/socket_stream.hpp>
#include <ext/net/http/http_types.hpp>

namespace ext::net::http
{
	class http_server_handler
	{
	public:
		virtual ~http_server_handler() = default;

		using result_type = std::variant<
			http_response,
			ext::future<http_response>
		>;

		virtual bool accept(const http_request & req, const socket_streambuf & sock) const = 0;		
		virtual auto process(http_request & req) const -> result_type = 0;
	};


	class simple_http_server_handler : public http_server_handler
	{
	public:
		using result_type = std::variant<
			std::string, http_response,
			ext::future<std::string>, ext::future<http_response>
		>;

		using function_type = std::variant<
			std::function<result_type()>,
			std::function<result_type(std::string &)>,
			std::function<result_type(http_request & req)>
		>;

	protected:
		struct call_dispatcher;
		struct result_dispatcher;

		std::vector<std::string> m_allowed_methods;
		std::string m_url;
		function_type m_function;

	public:
		virtual bool accept(const http_request & req, const socket_streambuf & sock) const override;
		virtual auto process(http_request & req) const -> http_server_handler::result_type override;
		virtual bool method_accepted(const std::string & method) const;

	public:
		simple_http_server_handler(std::string url, function_type function);
		simple_http_server_handler(std::vector<std::string> allowed_methods, std::string url, function_type function);
	};
}
