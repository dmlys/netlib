#include <ext/net/http/http_server.hpp>
#include <ext/net/http/http_server_impl_ext.hpp>
#include <ext/net/http/http_server_logging_helpers.hpp>

#include <ext/join_into.hpp>
#include <ext/stream_filtering/filter_types.hpp>
#include <ext/stream_filtering/filtering.hpp>
#include <boost/iterator/transform_iterator.hpp>

namespace ext::net::http
{
	static std::string filter_names(const std::vector<std::unique_ptr<ext::stream_filtering::filter>> & filters)
	{
		auto name = [](auto & filter) { return filter->name(); };
		auto first = boost::make_transform_iterator(filters.begin(), name);
		auto last  = boost::make_transform_iterator(filters.end(),   name);
		
		return ext::join(boost::make_iterator_range(first, last), ", ");
	}
	
	void http_server::prepare_request_http_body_filtering(processing_context * context)
	{
		assert(context->filter_ctx);
		
		auto & ctx = context->filter_ctx->request_streaming_ctx;
		assert(not ctx.filters.empty());
		
		SOCK_LOG_DEBUG("preparing request http body filtering, filters are: {}", filter_names(ctx.filters));
		ctx.params = context->filter_ctx->filter_params;
		preprocess_processing_parameters(ctx.params);
				
		ctx.data_contexts.resize(ctx.filters.size() + 1);
		ctx.buffers.resize(ctx.filters.size() - 1);
		
		const std::size_t buffer_size = std::clamp(ctx.params.default_buffer_size, ctx.params.minimum_buffer_size, ctx.params.maximum_buffer_size);
		
		for (auto & buffer : ctx.buffers)
			buffer.resize(buffer_size);
		
		for (unsigned i = 0; i < ctx.buffers.size(); ++i)
		{
			auto & dctx = ctx.data_contexts[i + 1];
			auto & buffer = ctx.buffers[i];
			dctx.data_ptr = buffer.data();
			dctx.capacity = buffer.size();
			//dctx.finished = false;
		}
	}
	
	void http_server::filter_request_http_body(processing_context * context)
	{
		assert(context->filter_ctx);
		
		auto & ctx    = context->filter_ctx->request_streaming_ctx;
		auto & input  = context->request_raw_buffer;
		auto & output = context->request_filtered_buffer;
		EXT_UNUSED(input, output); // unused
		
		assert(not ctx.filters.empty());
		
		auto & source_dctx = ctx.data_contexts.front();
		auto & dest_dctx   = ctx.data_contexts.back();
		
		// do filtering
		for (;;)
		{
			ext::stream_filtering::filter_step(ctx);
			
			auto source_unconsumed = source_dctx.written - source_dctx.consumed;
			auto source_threshold  = ext::stream_filtering::fullbuffer_threshold(source_dctx.capacity, ctx.params);
			auto dest_threshold    = ext::stream_filtering::fullbuffer_threshold(dest_dctx.capacity, ctx.params);
			
			if (dest_dctx.finished) break;
			if (source_unconsumed <  source_threshold) break;
			if (dest_dctx.written >= dest_threshold)   break;
		}
		
		
		SOCK_LOG_DEBUG("filtering request http body with source_dctx = {}/{}/{}, dest_dctx = {}/{}/{}",
		               source_dctx.written, source_dctx.consumed, source_dctx.finished ? 'f' : 'm',
		               dest_dctx.capacity, dest_dctx.written, source_dctx.finished ? 'f' : 'm' );
		
		
		// post filtering processing, check if we finished, have trailing data, etc				
		if (dest_dctx.finished)
		{
			auto trailing = source_dctx.written - source_dctx.consumed;
			if (not source_dctx.finished or trailing)
			{
				// Trailing request data after filters are finished. This is a error
				// (for example gzip filter done, but there is some trailing data)
				SOCK_LOG_WARN("http request body have trailing data, after filters are finished, at least {} bytes and {}",
				              trailing, source_dctx.finished ? "read everything from socket" : "have more unread data from socket");
				
				//response = create_bad_request_response(sock, connection_action_type::close);
				context->conn_action = connection_action_type::close;
				return; //&http_server::handle_response;
			}
		}
		
		return;
	}
	
	void http_server::prepare_response_http_body_filtering(processing_context * context)
	{
		assert(context->filter_ctx);
		
		auto & ctx = context->filter_ctx->response_streaming_ctx;
		assert(not ctx.filters.empty());
		
		SOCK_LOG_DEBUG("preparing response http body filtering, filters are: {}", filter_names(ctx.filters));
		ctx.params = context->filter_ctx->filter_params;
		preprocess_processing_parameters(ctx.params);
		
		ctx.data_contexts.resize(ctx.filters.size() + 1);
		ctx.buffers.resize(ctx.filters.size() - 1);
		
		const std::size_t buffer_size = std::clamp(ctx.params.default_buffer_size, ctx.params.minimum_buffer_size, ctx.params.maximum_buffer_size);
		
		for (auto & buffer : ctx.buffers)
			buffer.resize(buffer_size);
		
		for (unsigned i = 0; i < ctx.buffers.size(); ++i)
		{
			auto & dctx = ctx.data_contexts[i + 1];
			auto & buffer = ctx.buffers[i];
			dctx.data_ptr = buffer.data();
			dctx.capacity = buffer.size();
			//dctx.finished = false;
		}
	}
	
	void http_server::filter_response_http_body(processing_context * context)
	{
		assert(context->filter_ctx);
		
		auto & ctx    = context->filter_ctx->response_streaming_ctx;
		auto & input  = context->response_raw_buffer;
		auto & output = context->response_filtered_buffer;
		EXT_UNUSED(input, output);
		
		assert(not ctx.filters.empty());
		
		auto & source_dctx = ctx.data_contexts.front();
		auto & dest_dctx   = ctx.data_contexts.back();
		
		SOCK_LOG_DEBUG("filtering response http body with source_dctx = {}/{}/{}, dest_dctx.capacity = {}",
		               source_dctx.written, source_dctx.consumed, source_dctx.finished ? 'f' : 'm', dest_dctx.capacity);
		
		// do filtering
		for (;;)
		{
			ext::stream_filtering::filter_step(ctx);
			
			auto source_unconsumed = source_dctx.written - source_dctx.consumed;
			auto source_threshold  = ext::stream_filtering::fullbuffer_threshold(source_dctx.capacity, ctx.params);
			auto dest_threshold    = ext::stream_filtering::fullbuffer_threshold(dest_dctx.capacity, ctx.params);
			
			if (dest_dctx.finished) break;
			if (source_unconsumed <  source_threshold) break;
			if (dest_dctx.written >= dest_threshold)   break;
		}
		
		if (dest_dctx.finished)
		{
			// post filtering processing, check if we finished, have trailing data, etc
			auto trailing = source_dctx.written - source_dctx.consumed;
			if (not source_dctx.finished or trailing)
			{
				// Trailing response data after filters are finished. This is a error
				// (for example gzip filter done, but there is some trailing data)
				SOCK_LOG_WARN("http response body have trailing data, after filters are finished, at least {} bytes and {}",
				              trailing, source_dctx.finished ? "read everything from socket" : "have more unread data");
				
				context->conn_action = connection_action_type::close;
				return;
			}
		}
		
		return;
	}
}
