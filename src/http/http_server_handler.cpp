#include <ext/net/http/http_server_handler.hpp>
#include <ext/strings/aci_string.hpp>
#include <ext/functors/ctpred.hpp>
#include <boost/algorithm/string.hpp>

namespace ext::net::http
{
	bool simple_http_server_handler::method_accepted(const std::string & method) const
	{
		ext::ctpred::equal_to<ext::aci_char_traits> eq;
		if (m_allowed_methods.empty())
			return eq(method, "GET") or eq(method, "PUT") or eq(method, "POST");

		for (const auto & allowd_method : m_allowed_methods)
			if (eq(method, allowd_method)) return true;

		return false;
	}

	bool simple_http_server_handler::accept(const http_request & req, const socket_streambuf & sock) const
	{
		if (not method_accepted(req.method)) return false;
		if (not boost::starts_with(req.url, m_url)) return false;

		auto first = req.url.begin() + m_url.size();
		auto last  = req.url.end();

		while (first != last and *first == '/')
			++first;

		return first == last or *first == '?' or *first == '#';
	}

	struct simple_http_server_handler::result_dispatcher
	{
		template <class Type>
		static http_response make_response(Type && body) { http_response resp; resp.http_code = 200; resp.status = "OK"; resp.body = std::move(body); return resp; }

		http_server_handler::result_type operator()(std::nullopt_t val) const { return val; }
		http_server_handler::result_type operator()(http_response && resp) const { return std::move(resp); }
		
		template <class Type>
		http_server_handler::result_type operator()(Type && body) const { return make_response(std::move(body)); }
		
		http_server_handler::result_type operator()(ext::future<std::nullopt_t> fresp) const { return fresp; }
		http_server_handler::result_type operator()(ext::future<http_response> fresp)  const { return fresp; }
		
		template <class Type>
		http_server_handler::result_type operator()(ext::future<Type> fresp) const { return fresp.then([](auto f) { return make_response(f.get()); }); }
	};

	struct simple_http_server_handler::call_dispatcher
	{
		http_request * request;

		http_server_handler::result_type operator()(const std::function<result_type(std::string & )>                            & func)  const { return std::visit(result_dispatcher(), func(std::get<std::string>(request->body))); }
		http_server_handler::result_type operator()(const std::function<result_type(std::vector<char> & )>                      & func)  const { return std::visit(result_dispatcher(), func(std::get<std::vector<char>>(request->body))); }
		http_server_handler::result_type operator()(const std::function<result_type(std::unique_ptr<std::streambuf> &)>         & func)  const { return std::visit(result_dispatcher(), func(std::get<std::unique_ptr<std::streambuf>>(request->body))); }
		http_server_handler::result_type operator()(const std::function<result_type(std::unique_ptr<async_http_body_source> &)> & func)  const { return std::visit(result_dispatcher(), func(std::get<std::unique_ptr<async_http_body_source>>(request->body))); }
		http_server_handler::result_type operator()(const std::function<result_type(null_body_type)>                            & func)  const { return std::visit(result_dispatcher(), func(std::get<null_body_type>(request->body))); }
		
		http_server_handler::result_type operator()(const std::function<result_type()> & func)                const { return std::visit(result_dispatcher(), func()); }
		http_server_handler::result_type operator()(const std::function<result_type(http_request & )> & func) const { return std::visit(result_dispatcher(), func(*request)); }
	};

	auto simple_http_server_handler::process(http_request & req) const -> http_server_handler::result_type
	{
		return std::visit(call_dispatcher{&req}, m_function);
	}

	http_body_type simple_http_server_handler::deduce_body_type(const body_function_types & function) noexcept
	{
		return static_cast<http_body_type>(std::min<unsigned>(function.index(), 4));
		//switch (auto type = static_cast<http_body_type>(function.index()))
		//{
		//	case http_body_type::string:
		//	case http_body_type::vector:
		//	case http_body_type::stream:
		//	case http_body_type::async:
		//	case http_body_type::null:
		//		return type;
		//		
		//	default:
		//		return http_body_type::null;
		//}
	}
	
	simple_http_server_handler::simple_http_server_handler(std::string url, body_function_types function)
	    : m_url(std::move(url)), m_wanted_body_type(deduce_body_type(function)), m_function(convert(std::move(function)))
	{
	
	}

	simple_http_server_handler::simple_http_server_handler(std::vector<std::string> allowed_methods, std::string url, body_function_types function)
	    : m_allowed_methods(std::move(allowed_methods)), m_url(std::move(url)), m_wanted_body_type(deduce_body_type(function)), m_function(convert(std::move(function)))
	{

	}
	
	simple_http_server_handler::simple_http_server_handler(std::string url, request_function_type function, http_body_type wanted_body_type)
	    : m_url(std::move(url)), m_wanted_body_type(wanted_body_type), m_function(convert(std::move(function)))
	{
	
	}
	
	simple_http_server_handler::simple_http_server_handler(std::vector<std::string> allowed_methods, std::string url, request_function_type function, http_body_type wanted_body_type)
	    : m_allowed_methods(std::move(allowed_methods)), m_url(std::move(url)), m_wanted_body_type(wanted_body_type), m_function(convert(std::move(function)))
	{
	
	}
}
