#pragma once
#include <memory>
#include <optional>
#include <string_view>

#include <variant>
#include <any>

#include <boost/mp11.hpp>
#include <ext/intrusive_ptr.hpp>
#include <ext/library_logger/logger.hpp>
#include <ext/stream_filtering/filter_types.hpp>

#include <ext/net/http/http_types.hpp>

namespace ext::net::http
{
	class http_filter_base;
	class http_prefilter;
	class http_postfilter;
	class http_server_filter_control;
	
	class http_filter_base : public ext::intrusive_atomic_counter<http_filter_base>
	{
	protected:
		ext::library_logger::logger * m_logger = nullptr;

	public:
		static constexpr unsigned default_order = std::numeric_limits<unsigned>::max() / 2;

	public:
		virtual ~http_filter_base() = default;
		/// will be called by http_server, passing internal logger
		virtual void set_logger(ext::library_logger::logger * logger) { m_logger = logger; }
	};

	class http_prefilter : virtual public http_filter_base
	{
	public:
		/// override to change execution order of this filter
		virtual unsigned preorder() const noexcept { return default_order; }
		virtual void prefilter(http_server_filter_control & control) const = 0;
	};

	class http_postfilter : virtual public http_filter_base
	{
	public:
		/// override to change execution order of this filter
		virtual unsigned postorder() const noexcept { return default_order; }
		virtual void postfilter(http_server_filter_control & control) const = 0;
	};
	
	
	/// Interface implemented by http_server, intended to communicate by filters with http_server.
	/// Provides access to request, response, allows adding filters, etc.
	class http_server_filter_control
	{
	public:
		using filter = ext::stream_filtering::filter;
		using property = std::variant<bool, long, std::string, std::any>;
		
	public:
		virtual void request_filter_append(std::unique_ptr<filter> filter) = 0;
		virtual void request_filter_prepend(std::unique_ptr<filter> filter) = 0;
		virtual void request_filters_clear() = 0;
		
		virtual void response_filter_append(std::unique_ptr<filter> filter) = 0;
		virtual void response_filter_prepend(std::unique_ptr<filter> filter) = 0;
		virtual void response_filters_clear() = 0;
		
	public:
		virtual auto request() -> http_request & = 0;
		virtual auto response() -> http_response & = 0;
		virtual void override_response(http_response resp) = 0;
		
	public:
		virtual auto get_property(std::string_view name) -> std::optional<property> = 0;
		virtual void set_property(std::string_view name, property prop) = 0;
		
	public:
		virtual ~http_server_filter_control() = default;
	};
	
	template <class Type>
	std::optional<Type> get_property(http_server_filter_control & control, std::string_view name)
	{
		auto result = control.get_property(name);
		if (not result) return std::nullopt;
		
		using property = http_server_filter_control::property;
		using type_idx = boost::mp11::mp_find<property, Type>;
		constexpr bool found = not boost::mp11::mp_same<type_idx, boost::mp11::mp_size<property>>::value;
				
		if constexpr(found)
		{
			return std::get<Type>(std::move(*result));
		}
		else
		{
			auto & any = std::get<std::any>(*result);
			auto * val = std::any_cast<Type>(&any);
			
			if (not val) return std::nullopt;
			else         return std::move(*val);
		}
	}
}
