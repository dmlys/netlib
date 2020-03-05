#pragma once
#include <optional>
#include <ext/intrusive_ptr.hpp>
#include <ext/library_logger/logger.hpp>
#include <ext/net/http/http_types.hpp>

namespace ext::net::http
{
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


	class http_headers_prefilter : virtual public http_filter_base
	{
	public:
		/// override to change execution order of this filter
		virtual unsigned preorder_headers() const noexcept { return default_order; }
		//virtual auto prefilter_headers(http_request & request) const -> std::optional<http_response> = 0;
		virtual auto prefilter_headers(http_request & request) const -> std::optional<http_response> = 0;
	};

	class http_full_prefilter : virtual public http_filter_base
	{
	public:
		/// override to change execution order of this filter
		virtual unsigned preorder_full() const noexcept { return default_order; }
		//virtual auto prefilter_headers(http_request & request) const -> std::optional<http_response> = 0;
		virtual auto prefilter_full(http_request & request) const -> std::optional<http_response> = 0;
	};

	class http_post_filter : virtual public http_filter_base
	{
	public:
		/// override to change execution order of this filter
		virtual unsigned postorder() const noexcept { return default_order; }
		virtual void postfilter(http_request & request, http_response & response) const = 0;
	};
}
