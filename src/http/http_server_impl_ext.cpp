#include <ext/net/socket_include.hpp>
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
	
	EXT_NORETURN inline static void throw_stream_read_failure()
	{
		throw std::runtime_error("ext::net::http_server::http_body_stream: stream read failure");
	}
	
	/************************************************************************/
	/*            http_body_streambuf_impl::closable_http_body_impl         */
	/************************************************************************/
	http_server::http_body_streambuf_impl::closable_http_body_impl::closable_http_body_impl(http_server * server, processing_context * context)
	    : m_server(server), m_context(context)
	{
		intrusive_ptr_add_ref(this);
		http_server::closable_http_body * expected = nullptr;
		if (context->body_closer.compare_exchange_strong(expected, this, std::memory_order_release))
		{
			m_context->parser.set_body_destination(m_parsed_data);
		}
		else
		{
			assert(expected == reinterpret_cast<http_server::closable_http_body *>(1));
			intrusive_ptr_release(this);
			this->close();
		}
	}
	
	void http_server::http_body_streambuf_impl::closable_http_body_impl::mark_working()
	{
		auto prev_value = m_interrupt_work_flag.fetch_xor(0x01, std::memory_order_relaxed);
		if (prev_value == 0x00)
			return;
		
		// interrupted by close call
		assert(prev_value == 0x01);
		m_interrupted = true;
		throw_interrupted();
	}
	
	void http_server::http_body_streambuf_impl::closable_http_body_impl::unmark_working()
	{
		unsigned expected = 0x01;
		if (m_interrupt_work_flag.compare_exchange_strong(expected, 0x00, std::memory_order_relaxed))
			return;
		
		m_closed_promise.set_value();
		m_interrupted = true;
		throw_interrupted();
	}
	
	void http_server::http_body_streambuf_impl::closable_http_body_impl::check_interrupted()
	{
		if (m_interrupted) throw_interrupted();
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
		auto prev_value = m_interrupt_work_flag.fetch_xor(0x01, std::memory_order_relaxed);
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
	
	auto http_server::http_body_streambuf_impl::underflow() -> int_type
	{
		m_interrupt_state->check_interrupted();
		
		if (m_interrupt_state->m_finished)
			return traits_type::eof();
		
		auto * context = m_interrupt_state->m_context;
		auto * server  = m_interrupt_state->m_server;
		auto & parsed_data = m_interrupt_state->m_parsed_data;
		
		for (;;)
		{
			parsed_data.clear();
			
			m_interrupt_state->mark_working();
			
			auto * m_logger = server->m_logger;
			auto & sock = context->sock;
			auto & parser = context->parser;
			
			SOCK_LOG_TRACE("http_body_streambuf_impl::underflow: reading from socket");
			assert(not sock.throw_errors());
			auto peeked = ext::net::http::peek(sock);
			EXT_UNUSED(peeked);
			
			m_interrupt_state->unmark_working();
			
			if (sock.last_error() == ext::net::sock_errc::error)
				sock.throw_last_error();
			
			//if (not peeked)
			//	throw_stream_read_failure();
			
			auto * ptr = sock.gptr();
			std::size_t data_len = sock.egptr() - ptr;
			
			server->log_read_buffer(sock.handle(), ptr, data_len);
			
			auto parsed = parser.parse_message(ptr, data_len);
			sock.gbump(static_cast<int>(parsed));
			m_interrupt_state->m_finished = parser.message_parsed();
			
			if (parsed_data.empty())
			{
				// no data available after parsing - we either finished or need more data from socket
				if (not m_interrupt_state->m_finished)
					continue; // repeat reading
				
				// finished - return eof
				return traits_type::eof();
			}
			
			auto * first = parsed_data.data();
			auto * last  = first + parsed_data.size();
			setg(first, first, last);
			
			return traits_type::to_int_type(*first);
		};
	}
	
	/************************************************************************/
	/*            async_http_body_source_impl::closable_http_body_impl      */
	/************************************************************************/
	http_server::async_http_body_source_impl::closable_http_body_impl::closable_http_body_impl(http_server * server, processing_context * context)
		: m_server(server), m_context(context)
	{
		intrusive_ptr_add_ref(this);
		http_server::closable_http_body * expected = nullptr;
		if (context->body_closer.compare_exchange_strong(expected, this, std::memory_order_release))
		{
			m_context->parser.set_body_destination(m_data);
		}
		else
		{
			assert(expected == reinterpret_cast<http_server::closable_http_body *>(1));
			intrusive_ptr_release(this);
			this->close();
		}
	}
	
	ext::future<void> http_server::async_http_body_source_impl::closable_http_body_impl::close()
	{
		return ext::make_ready_future();
	}
	
	auto http_server::async_http_body_source_impl::make_closed_result() const -> ext::future<chunk_type>
	{
		closed_exception ex("ext::net::http::http_server::async_http_body_source: interrupt, server is stopping");
		return ext::make_exceptional_future<chunk_type>(std::move(ex));		
	}
	
	auto http_server::async_http_body_source_impl::read_some(std::vector<char> buffer) -> ext::future<chunk_type>
	{
		if (m_interrupt_state->m_interrupted.load(std::memory_order_relaxed))
			return make_closed_result();
		
		if (m_interrupt_state->m_finished.load(std::memory_order_relaxed))
			return ext::make_ready_future<chunk_type>(std::nullopt);
		
		if (m_interrupt_state->m_pending_request.exchange(true, std::memory_order_relaxed))
			throw std::logic_error("ext::net::http::http_server::async_http_body_source: already have pending request");
		
		auto * server  = m_interrupt_state->m_server;
		auto * context = m_interrupt_state->m_context;
		
		buffer.clear();
		m_interrupt_state->m_data = std::move(buffer);
		m_interrupt_state->m_read_promise = {}; // reset;
		
		std::lock_guard lk(server->m_mutex);
		if (server->m_running)
		{
			auto method = &http_server::handle_request_async_body_source_parsing;
			server->submit_handler(lk, method, context);
			return m_interrupt_state->m_read_promise.get_future();			
		}
		else
		{
			m_interrupt_state->m_interrupted.store(true, std::memory_order_relaxed);
			m_interrupt_state->m_pending_request.store(false, std::memory_order_relaxed);
			m_interrupt_state->m_server = nullptr;
			m_interrupt_state->m_context = nullptr;
			return make_closed_result();
		}
	}
	
	http_server::async_http_body_source_impl::async_http_body_source_impl(http_server * server, processing_context * context)
	    : m_interrupt_state(ext::make_intrusive<closable_http_body_impl>(server, context))
	{
	
	}
}
