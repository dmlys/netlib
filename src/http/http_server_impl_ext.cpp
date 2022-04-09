#include <ext/net/socket_include.hpp>
#include <ext/stream_filtering/filtering.hpp>

#include <ext/net/http/http_server.hpp>
#include <ext/net/http/http_server_impl_ext.hpp>
#include <ext/net/http/http_server_logging_helpers.hpp>

namespace ext::net::http
{
	inline static bool peek(std::streambuf & sb)
	{
		typedef std::streambuf::traits_type traits_type;
		return not traits_type::eq_int_type(traits_type::eof(), sb.sgetc());
	}
	
	/************************************************************************/
	/*            http_body_streambuf_impl::closable_http_body_impl         */
	/************************************************************************/
	http_server::http_body_streambuf_impl::closable_http_body_impl::closable_http_body_impl(http_server * server, processing_context * context)
	    : m_server(server), m_context(context)
	{
		intrusive_ptr_add_ref(this);
		std::uintptr_t expected = 0;
		if (context->body_closer.compare_exchange_strong(expected, reinterpret_cast<std::uintptr_t>(this), std::memory_order_release))
		{
			m_filtered = m_context->filter_ctx and not m_context->filter_ctx->request_streaming_ctx.filters.empty();
			
			if (not m_filtered)
			{
				m_context->parser.set_body_destination(m_data);
				m_finished.store(m_context->parser.message_parsed(), std::memory_order_relaxed);
				m_underflow_method = &http_body_streambuf_impl::underflow_normal;
			}
			else
			{
				m_context->parser.set_body_destination(m_context->request_raw_buffer);
				m_finished.store(false, std::memory_order_relaxed);
				m_underflow_method = &http_body_streambuf_impl::underflow_filtered;
				
				m_server->prepare_request_http_body_filtering(m_context);
				auto & params = m_context->filter_ctx->request_streaming_ctx.params;
				auto & output = m_data;
				
				auto len = std::clamp(params.default_buffer_size, params.minimum_buffer_size, params.maximum_buffer_size);
				output.resize(std::max(output.capacity(), std::size_t(len)));
			}
		}
		else
		{
			assert(expected == 0x01);
			intrusive_ptr_release(this);
			this->close();
		}
	}
	
	void http_server::http_body_streambuf_impl::closable_http_body_impl::mark_working()
	{
		auto prev_value = m_interrupt_work_flag.fetch_xor(0x01, std::memory_order_relaxed);
		if (prev_value == 0x00)
		{
			std::atomic_thread_fence(std::memory_order_acquire);
			return;
		}
		
		// interrupted by close call
		assert(prev_value == 0x01);
		m_closed = true;
		throw_interrupted();
	}
	
	void http_server::http_body_streambuf_impl::closable_http_body_impl::unmark_working()
	{
		unsigned expected = 0x01;
		if (m_interrupt_work_flag.compare_exchange_strong(expected, 0x00, std::memory_order_release))
			return;
		
		m_closed_promise.set_value();
		m_closed = true;
		throw_interrupted();
	}
	
	void http_server::http_body_streambuf_impl::closable_http_body_impl::check_interrupted()
	{
		// this method is called in working state, should be m_interrupt_work_flag == 0x01,
		// unless close call was made
		if (m_interrupt_work_flag.load(std::memory_order_relaxed) == 0x00)
		{
			m_closed_promise.set_value();
			m_closed = true;
			throw_interrupted();
		}
	}
	
	EXT_NORETURN void http_server::http_body_streambuf_impl::closable_http_body_impl::throw_interrupted()
	{
		throw closed_exception("ext::net::http::http_server::http_body_stream: interrupt, server is stopping");
	}
	
	ext::future<void> http_server::http_body_streambuf_impl::closable_http_body_impl::close()
	{
		// will throw if future already was retrieved
		auto close_future = m_closed_promise.get_future();
		
		// see class description
		// probably memory_order_reaxed is enough, promise.set_value have memory_order_acq_rel constraint
		auto prev_value = m_interrupt_work_flag.fetch_xor(0x01, std::memory_order_acq_rel);
		if (prev_value == 0x00)
			m_closed_promise.set_value();
		else
		{
			assert(prev_value == 0x01);
			m_context->sock.interrupt();
			// m_closed_promise should be fulfilled by other side
		}
		
		return close_future;
	}


	http_server::http_body_streambuf_impl::http_body_streambuf_impl(http_server * server, processing_context * context)
	    : m_interrupt_state(ext::make_intrusive<closable_http_body_impl>(server, context))
	{
	
	}
	
	void http_server::http_body_streambuf_impl::read_parse_some()
	{		
		auto * context = m_interrupt_state->m_context;
		auto * server  = m_interrupt_state->m_server;
		
		auto * m_logger = server->m_logger;
		auto & sock = context->sock;
		auto & parser = context->parser;
		
		SOCK_LOG_TRACE("http_body_streambuf_impl::underflow: reading from socket");
		assert(not sock.throw_errors());
		auto peeked = ext::net::http::peek(sock);
		EXT_UNUSED(peeked);
		
		// will throw if interrupted
		m_interrupt_state->check_interrupted();
		
		if (sock.last_error() == ext::net::sock_errc::error)
			sock.throw_last_error();
		
		auto * ptr = sock.gptr();
		std::size_t data_len = sock.egptr() - ptr;
		
		server->log_read_buffer(sock.handle(), ptr, data_len);
		
		auto parsed = parser.parse_message(ptr, data_len);
		sock.gbump(static_cast<int>(parsed));
	}
	
	auto http_server::http_body_streambuf_impl::underflow_normal() -> int_type
	{
		assert(not m_interrupt_state->m_filtered);
		
		if (m_interrupt_state->m_finished.load(std::memory_order_relaxed))
			return traits_type::eof();
		
		auto & parsed_data = m_interrupt_state->m_data;
		parsed_data.clear();
		
		auto * context = m_interrupt_state->m_context;
		m_interrupt_state->mark_working();
		
		do read_parse_some();
		while (parsed_data.empty() and not context->parser.message_parsed());
		
		// those are from m_interrupt_state->m_data,
		// so those pointers will not dangle in case of close event from http_server
		char * first = parsed_data.data();
		char * last  = first + parsed_data.size();
		m_interrupt_state->m_finished.store(context->parser.message_parsed(), std::memory_order_relaxed);
		
		m_interrupt_state->unmark_working();
		
		setg(first, first, last);
		return first == last ? traits_type::eof() 
							 : traits_type::to_int_type(*first);
	}
	
	auto http_server::http_body_streambuf_impl::underflow_filtered() -> int_type
	{
		assert(m_interrupt_state->m_filtered);
		
		if (m_interrupt_state->m_finished.load(std::memory_order_relaxed))
			return traits_type::eof();
		
		m_interrupt_state->mark_working();
		
		auto * context = m_interrupt_state->m_context;
		auto * server  = m_interrupt_state->m_server;
		
		auto & parsed_data = context->request_raw_buffer;
		auto & filtered_data = m_interrupt_state->m_data;
		
		auto & source_dctx = context->filter_ctx->request_streaming_ctx.data_contexts.front();
		auto & dest_dctx = context->filter_ctx->request_streaming_ctx.data_contexts.back();
		auto & params = context->filter_ctx->request_streaming_ctx.params;
		
		for (;;)
		{
			auto unconsumed = source_dctx.written - source_dctx.consumed;
			auto threshold  = ext::stream_filtering::emptybuffer_threshold(params.default_buffer_size, params);
			
			// if less than 20% and source is not finished - read some
			if (unconsumed < threshold and not source_dctx.finished)
			{
				auto first = parsed_data.begin();
				auto last  = first + source_dctx.consumed;
				parsed_data.erase(first, last);
				
				do read_parse_some();
				while (parsed_data.empty() and not context->parser.message_parsed());
				
				// update/prepare source filtering context
				source_dctx.data_ptr = parsed_data.data();
				source_dctx.written = source_dctx.capacity = parsed_data.size();
				source_dctx.finished = context->parser.message_parsed();
				source_dctx.consumed = 0;
			}
			
			dest_dctx.data_ptr = filtered_data.data();
			dest_dctx.capacity = filtered_data.size();
			server->filter_request_http_body(context);
			
			unconsumed = dest_dctx.written - dest_dctx.consumed;
			threshold  = ext::stream_filtering::emptybuffer_threshold(dest_dctx.capacity, params);
			if (unconsumed < threshold and not dest_dctx.finished) continue;
			
			// those are from m_interrupt_state->m_data,
			// so those pointers will not dangle in case of close event from http_server
			char * first = dest_dctx.data_ptr + dest_dctx.consumed;
			char * last  = dest_dctx.data_ptr + dest_dctx.written;
			
			dest_dctx.written = dest_dctx.consumed = 0;
			m_interrupt_state->m_finished.store(dest_dctx.finished, std::memory_order_relaxed);
			
			m_interrupt_state->unmark_working();
			
			setg(first, first, last);
			return first == last ? traits_type::eof() 
			                     : traits_type::to_int_type(*first);
		};
	}
	
	auto http_server::http_body_streambuf_impl::underflow() -> int_type
	{
		return (this->*m_interrupt_state->m_underflow_method)();
	}
	
	
	
	/************************************************************************/
	/*            async_http_body_source_impl::closable_http_body_impl      */
	/************************************************************************/
	http_server::async_http_body_source_impl::closable_http_body_impl::closable_http_body_impl(http_server * server, processing_context * context)
		: m_server(server), m_context(context)
	{
		intrusive_ptr_add_ref(this);
		std::uintptr_t expected = 0;
		if (context->body_closer.compare_exchange_strong(expected, reinterpret_cast<std::uintptr_t>(this), std::memory_order_release))
		{
			m_filtered = m_context->filter_ctx and not m_context->filter_ctx->request_streaming_ctx.filters.empty();
			m_context->parser.set_body_destination(m_context->request_raw_buffer);
			
			if (not m_filtered)
				m_async_method = &http_server::handle_request_normal_async_source_body_parsing;
			else
			{
				m_async_method = &http_server::handle_request_filtered_async_source_body_parsing;
				
				m_server->prepare_request_http_body_filtering(m_context);
				auto & params = m_context->filter_ctx->request_streaming_ctx.params;
				auto & output = m_context->request_filtered_buffer;
				
				m_default_buffer_size = std::clamp(params.default_buffer_size, params.minimum_buffer_size, params.maximum_buffer_size);
				output.resize(std::max(output.capacity(), std::size_t(m_default_buffer_size)));
			}
		}
		else
		{
			assert(expected == 0x01);
			intrusive_ptr_release(this);
			this->close();
		}
	}
		
	auto http_server::async_http_body_source_impl::closable_http_body_impl::make_closed_exception() const -> closed_exception
	{
		return closed_exception("ext::net::http::http_server::async_http_body_source: interrupt, server is stopping");
	}
	
	auto http_server::async_http_body_source_impl::closable_http_body_impl::make_closed_result() const -> ext::future<chunk_type>
	{		
		return ext::make_exceptional_future<chunk_type>(make_closed_exception());
	}
	
	auto http_server::async_http_body_source_impl::closable_http_body_impl::take_result_promise() -> std::optional<ext::promise<chunk_type>>
	{
		// actually result can be set by 2 scenarios: 
		// 1. normal operation result: data or runtime exception result
		// 2. closed event, because of http_server stopping: closed exception result
		// 
		// 1 never concurates with itself, because we enforce one read_some operation at time
		// 2 never concurates with itself either - body never closed twice
		// so they only concurate with each other, and close can happen only once + sets closed flag.
		// 
		//
		// Set result only if there are: pending flag and result flag is not set
		// In normal situation this will always hold, except if close event came.
		// In that case it can set result earlier - it's ok, just forget about current normal result.
		// 
		// If close result comes after regular result - we can drop first one, we already set closed flag,
		// Any new read_some operation will just produce closed_exception immediately
		
		
		// set result flag and check if it was not already set
		unsigned prevstate = m_state_flags.load(std::memory_order_relaxed);
		unsigned newstate;
		
		do {
			if ((prevstate & pending_request_mask) == 0)
				return std::nullopt; // no pending request, it was already fulfiled
			
			if (prevstate & result_mask)
				return std::nullopt; // somebody already setting result
			
			newstate = prevstate | result_mask;
		} while (not m_state_flags.compare_exchange_weak(prevstate, newstate, std::memory_order_relaxed));
		
		// Promise have to be taken/moved from m_read_promise before reseting pending request flag,
		// otherwise new read_some call can potentialy happen before current result is set,
		// with m_read_promise is reset in read_some method, effectively abandoning current promise.  
		// 
		// But result must be set after pending request flag is set,
		// otherwise when client will try to request new data via read_some call from current future continuation,
		// he will got a error that there is already pending request.
		// Request is done, user should be ably to make new request.
		auto promise = std::move(m_read_promise);
		
		// this is to establish happens before ordering constraints,
		// moving promise should happen before storing to m_pending_request
		std::atomic_thread_fence(std::memory_order_release);
		// reset pending request and result flags
		m_state_flags.fetch_and(~(pending_request_mask | result_mask), std::memory_order_release);
		
		return promise;
	}
	
	void http_server::async_http_body_source_impl::closable_http_body_impl::set_value_result(chunk_type result)
	{
		auto opt_promise = take_result_promise();
		if (opt_promise) opt_promise->set_value(std::move(result));
	}
	
	void http_server::async_http_body_source_impl::closable_http_body_impl::set_exception_result(std::exception_ptr ex)
	{
		auto opt_promise = take_result_promise();
		if (opt_promise) opt_promise->set_exception(std::move(ex));
	}
	
	ext::future<void> http_server::async_http_body_source_impl::closable_http_body_impl::close()
	{
		m_state_flags.fetch_or(closed_mask, std::memory_order_relaxed);
		
		auto ex = make_closed_exception();
		set_exception_result(std::make_exception_ptr(std::move(ex)));
		
		// and return closed ready future
		return ext::make_ready_future();
	}
	
	auto http_server::async_http_body_source_impl::read_some(std::vector<char> buffer, std::size_t size) -> ext::future<chunk_type>
	{
		constexpr unsigned closed_mask          = closable_http_body_impl::closed_mask;
		constexpr unsigned finished_mask        = closable_http_body_impl::finished_mask;
		constexpr unsigned pending_request_mask = closable_http_body_impl::pending_request_mask;
		// check closed flag
		if (m_interrupt_state->m_state_flags.load(std::memory_order_relaxed) & closed_mask)
			return m_interrupt_state->make_closed_result();
		// check finished flag
		if (m_interrupt_state->m_state_flags.load(std::memory_order_relaxed) & finished_mask)
			return ext::make_ready_future<chunk_type>(std::nullopt);
		// set pending_request flag and check if it was not already set
		if (m_interrupt_state->m_state_flags.fetch_or(pending_request_mask, std::memory_order_relaxed) & pending_request_mask)
			throw std::logic_error("ext::net::http::http_server::async_http_body_source: already have pending request");
		
		// this is to establish happens before ordering constraints,
		// reading and checking m_pending_request should happen defore reseting m_read_promise
		std::atomic_thread_fence(std::memory_order_acquire);
		decltype (buffer) * dest;
		
		if (not m_interrupt_state->m_filtered)
		{
			buffer.clear();
			dest = &m_interrupt_state->m_context->request_raw_buffer;
		}
		else
		{
			auto bufsize = std::max(size, m_interrupt_state->m_default_buffer_size);
			buffer.resize(bufsize);
			
			dest = &m_interrupt_state->m_context->request_filtered_buffer;
		}
		
		m_interrupt_state->m_asked_size = size;
		m_interrupt_state->m_read_promise = {}; // reset;
		std::atomic_thread_fence(std::memory_order_release);
		
		// It is important to retrieve this future before submit handler
		auto result_future = m_interrupt_state->m_read_promise.get_future();
		
		auto * server  = m_interrupt_state->m_server;
		auto * context = m_interrupt_state->m_context;
		
		std::lock_guard lk(server->m_mutex);
		if (server->m_running)
		{
			*dest = std::move(buffer);
			server->submit_handler(lk, m_interrupt_state->m_async_method, context);
			// during this submit_handler handler actually can be completed completely
			// and even set_value_result/set_exception_result can be called, promise can be reset
			// so future should be retrieved before
			return result_future;
		}
		else
		{
			m_interrupt_state->m_state_flags.fetch_or(closed_mask, std::memory_order_relaxed);            // set   closed flag
			m_interrupt_state->m_state_flags.fetch_and(~pending_request_mask, std::memory_order_relaxed); // reset pending_request flag
			m_interrupt_state->m_server = nullptr;
			m_interrupt_state->m_context = nullptr;
			return m_interrupt_state->make_closed_result();
		}
	}
	
	http_server::async_http_body_source_impl::async_http_body_source_impl(http_server * server, processing_context * context)
	    : m_interrupt_state(ext::make_intrusive<closable_http_body_impl>(server, context))
	{
	
	}
	
	/************************************************************************/
	/*               http_server::http_server_filter_control impl           */
	/************************************************************************/
	auto http_server::http_server_control::acquire_filtering_context() -> filtering_context &
	{
		if (not m_context->filter_ctx)
			m_context->filter_ctx = std::make_unique<filtering_context>();

		return *m_context->filter_ctx;
	}
	
	auto http_server::http_server_control::acquire_property_map() -> property_map &
	{
		if (not m_context->property_map)
			m_context->property_map = std::make_unique<property_map>();
		
		return *m_context->property_map;
	}
	
	void http_server::http_server_control::request_filter_append(std::unique_ptr<filter> filter)
	{
		auto & fctx = acquire_filtering_context();
		fctx.request_streaming_ctx.filters.push_back(std::move(filter));
	}
	
	void http_server::http_server_control::request_filter_prepend(std::unique_ptr<filter> filter)
	{
		auto & fctx = acquire_filtering_context();
		auto & filters = fctx.request_streaming_ctx.filters;
		filters.insert(filters.begin(), std::move(filter));
	}
	
	void http_server::http_server_control::request_filters_clear()
	{
		if (not m_context->filter_ctx)
			return;
		
		m_context->filter_ctx->request_streaming_ctx.filters.clear();
	}
	
	void http_server::http_server_control::response_filter_append(std::unique_ptr<filter> filter)
	{
		auto & fctx = acquire_filtering_context();
		fctx.response_streaming_ctx.filters.push_back(std::move(filter));
	}
	
	void http_server::http_server_control::response_filter_prepend(std::unique_ptr<filter> filter)
	{
		auto & fctx = acquire_filtering_context();
		auto & filters = fctx.response_streaming_ctx.filters;
		filters.insert(filters.begin(), std::move(filter));
	}
	
	void http_server::http_server_control::response_filters_clear()
	{
		if (not m_context->filter_ctx)
			return;
		
		m_context->filter_ctx->response_streaming_ctx.filters.clear();
	}
	
	void http_server::http_server_control::set_response_final() noexcept
	{
		m_context->response_is_final = true;
	}
	
	bool http_server::http_server_control::is_response_final() const noexcept
	{
		return m_context->response_is_final;
	}
	
	auto http_server::http_server_control::socket() const -> const ext::net::socket_streambuf & 
	{
		return m_context->sock;
	}
	
	auto http_server::http_server_control::request() -> http_request &
	{
		return m_context->request;
	}
	
	auto http_server::http_server_control::response() -> http_response &
	{
		auto * response_ptr = std::get_if<http_response>(&m_context->response);
		if (response_ptr) return *response_ptr;
		
		throw std::runtime_error("http_server::http_server_filter_control: http response not available");
	}
	
	void http_server::http_server_control::set_response(http_response && resp)
	{
		if (not std::holds_alternative<null_response_type>(m_context->response))
			throw std::runtime_error("http_server::http_server_filter_control: http response is already set");
		
		m_context->response = std::move(resp);
	}
	
	void http_server::http_server_control::override_response(http_response && resp, bool final)
	{
		m_context->response = std::move(resp);
		m_context->response_is_final = final;
	}
	
	void http_server::http_server_control::override_response(null_response_type)
	{
		m_context->response_is_null = true;
		m_context->response_is_final = true; // unnecessary
	}
	
	auto http_server::http_server_control::get_property(std::string_view name) const -> std::optional<property>
	{
		if (not m_context->property_map) return std::nullopt;
		
		auto & pmap = *m_context->property_map;
		std::string key(name);
		auto it = pmap.find(key);
		if (it == pmap.end()) return std::nullopt;
		
		return it->second;
	}
	
	void http_server::http_server_control::set_property(std::string_view name, property prop)
	{
		auto & pmap = acquire_property_map();
		pmap.insert_or_assign(std::string(name), std::move(prop));
	}
}
