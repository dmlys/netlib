#pragma once
#include <memory>
#include <limits>
#include <string_view>

#include <variant>
#include <any>

#include <ext/intrusive_ptr.hpp>
#include <ext/log/logger.hpp>


namespace ext::net::http
{
	class http_filter_base;
	class http_prefilter;
	class http_postfilter;
	class http_server_control;
	
	class http_filter_base : public ext::intrusive_atomic_counter<http_filter_base>
	{
	protected:
		ext::log::logger * m_logger = nullptr;

	public:
		static constexpr unsigned default_order = std::numeric_limits<unsigned>::max() / 2;

	public:
		virtual ~http_filter_base() = default;
		/// will be called by http_server, passing internal logger
		virtual void set_logger(ext::log::logger * logger) { m_logger = logger; }
	};

	class http_prefilter : virtual public http_filter_base
	{
	public:
		/// override to change execution order of this filter
		virtual unsigned preorder() const noexcept { return default_order; }
		virtual void prefilter(http_server_control & control) const = 0;
	};

	class http_postfilter : virtual public http_filter_base
	{
	public:
		/// override to change execution order of this filter
		virtual unsigned postorder() const noexcept { return default_order; }
		virtual void postfilter(http_server_control & control) const = 0;
	};
}
