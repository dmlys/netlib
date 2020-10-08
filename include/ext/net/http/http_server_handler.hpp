#pragma once
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <functional>

#include <ext/future.hpp>
#include <ext/library_logger/logger.hpp>
#include <ext/net/socket_stream.hpp>
#include <ext/net/http/http_types.hpp>

#include <boost/mp11.hpp>

namespace ext::net::http
{
	class http_server_handler
	{
	protected:
		ext::library_logger::logger * m_logger = nullptr;

	public:
		static constexpr unsigned default_order = std::numeric_limits<unsigned>::max() / 2;

	public:
		/// will be called by http_server, passing internal logger
		virtual void set_logger(ext::library_logger::logger * logger) { m_logger = logger; }
		/// override to change search order of this handler
		virtual unsigned order() const noexcept { return default_order; }

	public:
		using result_type = std::variant<
			std::nullopt_t,  // no answer at all, connection will be closed
			http_response,

			// async variants
			ext::future<std::nullopt_t>,
			ext::future<http_response>
		>;

		virtual auto wanted_body_type() const noexcept -> http_body_type = 0;
		virtual bool accept(const http_request & req, const socket_streambuf & sock) const = 0;
		virtual auto process(http_request & req) const -> result_type = 0;

		virtual ~http_server_handler() = default;
	};


	class simple_http_server_handler : public http_server_handler
	{
	public:
		using result_types = boost::mp11::mp_list<
			// direct result types
			std::nullopt_t, // TODO: introduce special type
			http_response,
			// http body types
			std::string,
			std::vector<char>,
			std::unique_ptr<std::streambuf>,
			std::unique_ptr<async_http_body_source>,
			null_body_type
		>;
		
		using result_types2 = boost::mp11::mp_append<
			result_types,
			boost::mp11::mp_transform_q<boost::mp11::mp_quote<ext::future>, result_types>
		>;
		
		using result_type = boost::mp11::mp_rename<result_types2, std::variant>;
		
		//using result_type = std::variant<
		//	// direct result types
		//	std::nullopt_t,
		//	http_response,
		//	// http body types
		//	std::string,
		//	std::vector<char>,
		//	std::unique_ptr<std::streambuf>,
		//	std::unique_ptr<async_http_body_source>,
		//	null_body_type
		//
		//	// async variants
		//>;

		using body_function_types = std::variant<
			std::function<result_type(std::string &)>,
			std::function<result_type(std::vector<char> &)>,
			std::function<result_type(std::unique_ptr<std::streambuf> &)>,
			std::function<result_type(std::unique_ptr<async_http_body_source> &)>,
			std::function<result_type(null_body_type)>,
			std::function<result_type()>
		>;
		
		using request_function_type = std::function<result_type(http_request & req)>;
		
		using function_type = boost::mp11::mp_append<
			body_function_types, boost::mp11::mp_list<request_function_type>
		>;
		
		//using function_type = std::variant<
		//	std::function<result_type()>,
		//	std::function<result_type(std::string &)>,
		//	std::function<result_type(http_request & req)>
		//>;

	protected:
		struct call_dispatcher;
		struct result_dispatcher;

		std::vector<std::string> m_allowed_methods;
		std::string m_url;
		http_body_type m_wanted_body_type;
		function_type m_function;

	public:
		virtual auto wanted_body_type() const noexcept -> http_body_type override { return m_wanted_body_type; }
		virtual bool accept(const http_request & req, const socket_streambuf & sock) const override;
		virtual auto process(http_request & req) const -> http_server_handler::result_type override;
		virtual bool method_accepted(const std::string & method) const;

	protected:
		static http_body_type deduce_body_type(const body_function_types & function) noexcept;
		static function_type convert(body_function_types function) { return std::visit([](auto func) -> function_type { return func; }, std::move(function)); }
		static function_type convert(request_function_type function) { return function; }
		
	public:
		simple_http_server_handler(std::string url, body_function_types function);
		simple_http_server_handler(std::vector<std::string> allowed_methods, std::string url, body_function_types function);
		simple_http_server_handler(std::string url, request_function_type function, http_body_type wanted_body_type = http_body_type::string);
		simple_http_server_handler(std::vector<std::string> allowed_methods, std::string url, request_function_type function, http_body_type wanted_body_type = http_body_type::string);
	};
}
