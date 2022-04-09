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

	bool simple_http_server_handler::accept(http_server_control & control) const
	{
		auto & req = control.request();
		
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

		http_server_handler::result_type operator()(null_response_type val) const { return val; }
		http_server_handler::result_type operator()(http_response && resp) const { return std::move(resp); }
		
		template <class Type>
		http_server_handler::result_type operator()(Type && body) const { return make_response(std::move(body)); }
		
		http_server_handler::result_type operator()(ext::future<null_response_type> fresp) const { return fresp; }
		http_server_handler::result_type operator()(ext::future<http_response> fresp)  const { return fresp; }
		
		template <class Type>
		http_server_handler::result_type operator()(ext::future<Type> fresp) const { return fresp.then([](auto f) { return make_response(f.get()); }); }
	};

	struct simple_http_server_handler::call_dispatcher
	{
		http_server_control * control;

		http_server_handler::result_type operator()(const std::function<result_type(std::string & )>                            & func)  const { return std::visit(result_dispatcher(), func(std::get<std::string>(control->request().body))); }
		http_server_handler::result_type operator()(const std::function<result_type(std::vector<char> & )>                      & func)  const { return std::visit(result_dispatcher(), func(std::get<std::vector<char>>(control->request().body))); }
		http_server_handler::result_type operator()(const std::function<result_type(std::unique_ptr<std::streambuf> &)>         & func)  const { return std::visit(result_dispatcher(), func(std::get<std::unique_ptr<std::streambuf>>(control->request().body))); }
		http_server_handler::result_type operator()(const std::function<result_type(std::unique_ptr<async_http_body_source> &)> & func)  const { return std::visit(result_dispatcher(), func(std::get<std::unique_ptr<async_http_body_source>>(control->request().body))); }
		http_server_handler::result_type operator()(const std::function<result_type(http_request & )>                           & func)  const { return std::visit(result_dispatcher(), func(control->request())); }
		http_server_handler::result_type operator()(const std::function<result_type(null_body_type)>                            & func)  const { return std::visit(result_dispatcher(), func(std::get<null_body_type>(control->request().body))); }
		
		http_server_handler::result_type operator()(const std::function<result_type()> & func)                       const { return std::visit(result_dispatcher(), func()); }
		http_server_handler::result_type operator()(const std::function<result_type(http_server_control & )> & func) const { return std::visit(result_dispatcher(), func(*control)); }
	};

	auto simple_http_server_handler::process(http_server_control & control) const -> http_server_handler::result_type
	{
		return std::visit(call_dispatcher{&control}, m_function);
	}

	template <std::size_t index, class arg_type>
	constexpr bool deduce_body_test = std::is_same_v<
		std::variant_alternative_t<index, simple_http_server_handler::body_function_types>,
		std::function<simple_http_server_handler::result_type(arg_type)>
	>;
	
	template <std::size_t index>
	constexpr bool deduce_body_test<index, void> = std::is_same_v<
		std::variant_alternative_t<index, simple_http_server_handler::body_function_types>,
		std::function<simple_http_server_handler::result_type()>
	>;
	
	http_body_type simple_http_server_handler::deduce_body_type(const body_function_types & function) noexcept
	{
		static_assert(std::variant_size_v<body_function_types> == 6);
		static_assert(deduce_body_test<0, std::string &>);
		static_assert(deduce_body_test<1, std::vector<char> &>);
		static_assert(deduce_body_test<2, std::unique_ptr<std::streambuf> &>);
		static_assert(deduce_body_test<3, std::unique_ptr<async_http_body_source> &>);
		static_assert(deduce_body_test<4, null_body_type>);
		static_assert(deduce_body_test<5, void>);
		
		//0 - std::string
		//1 - std::vector<char>
		//2 - std::unique_ptr<std::streambuf>
		//3 - std::unique_ptr<async_http_body_source>
		//4 - null_body_type
		//5 - ()
		switch (auto index = function.index())
		{
			case 0: return http_body_type::string;
			case 1: return http_body_type::vector;
			case 2: return http_body_type::stream;
			case 3: return http_body_type::async;
			case 4: return http_body_type::null;
			case 5: return http_body_type::null;
			
			default: EXT_UNREACHABLE();
		}
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
