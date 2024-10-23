#include <ext/net/http/http_types.hpp>
#include <ext/itoa.hpp>

namespace ext::net::http
{
	namespace
	{
		struct http_body_print_visitor
		{
			std::string_view operator()(const std::string       & str ) const noexcept { return str; }
			std::string_view operator()(const std::vector<char> & data) const noexcept { return std::string_view(data.data(), data.size()); }
			std::string_view operator()(const std::unique_ptr<std::streambuf> & ) const noexcept { return "<std::streambuf>"; }
			std::string_view operator()(const std::unique_ptr<async_http_body_source> & ) const noexcept { return "<ext::net::http::async_http_body_source>"; }
			std::string_view operator()(const lstream & l) const noexcept { return "<ext::net::http::lstream>"; }
			std::string_view operator()(null_body_type) const noexcept { return "<ext::net::http::null_body>"; }
		};
		
		struct http_body_size_visitor
		{
			std::optional<std::size_t> operator()(const std::string       & str ) const noexcept { return str.size(); }
			std::optional<std::size_t> operator()(const std::vector<char> & data) const noexcept { return data.size(); }
			std::optional<std::size_t> operator()(const std::unique_ptr<std::streambuf> & ) const noexcept { return std::nullopt; }
			std::optional<std::size_t> operator()(const std::unique_ptr<async_http_body_source> & ) const noexcept { return std::nullopt; }
			std::optional<std::size_t> operator()(const lstream & ls) const noexcept { return ls.size; }
			std::optional<std::size_t> operator()(null_body_type) const noexcept { return 0; }
		};
				
		struct http_body_clear_visitor
		{
			void operator()(std::string       & str ) const noexcept { return str.clear(); }
			void operator()(std::vector<char> & data) const noexcept { return data.clear(); }
			void operator()(std::unique_ptr<std::streambuf> & ) const noexcept { }
			void operator()(std::unique_ptr<async_http_body_source> & ) const noexcept { }
			void operator()(lstream & ) const noexcept { }
			void operator()(null_body_type) const noexcept { }
		};
		
		struct http_body_copy_cp_visitor
		{
			http_body operator()(const std::string & str) const { return str; }
			http_body operator()(const std::vector<char> & data) const { return data; }
			http_body operator()(std::unique_ptr<std::streambuf> & sbuf) const { return std::move(sbuf); }
			http_body operator()(std::unique_ptr<async_http_body_source> & src) const { return std::move(src); }
			http_body operator()(lstream & lstream) const { return std::move(lstream); }
			http_body operator()(null_body_type) const { return null_body; }
		};
		
		struct http_body_copy_chk_visitor
		{
			http_body operator()(const std::string & str) const { return str; }
			http_body operator()(const std::vector<char> & data) const { return data; }
			http_body operator()(const std::unique_ptr<std::streambuf> & sbuf) const { throw std::runtime_error("Can't copy from http_body:std::streambuf"); }
			http_body operator()(const std::unique_ptr<async_http_body_source> & src) const { throw std::runtime_error("Can't copy from http_body:async_http_body_source"); }
			http_body operator()(const lstream & lstream) const { throw std::runtime_error("Can't copy from http_body:lstream"); }
			http_body operator()(null_body_type) const { return null_body; }
		};
	}
	
	http_header_view::operator http_header() const
	{
		return {
			std::string(name.data(), name.size()),
			std::string(value.data(), value.size())
		};
	}

	http_header::operator http_header_view() const noexcept
	{
		return http_header_view {
			name,
			value
		};
	}
	
	std::optional<std::size_t> size(const http_body & body) noexcept
	{
		return std::visit(http_body_size_visitor(), body);
	}
	
	void copy_meta(const http_request & src, http_request & dest)
	{
		dest.http_version = src.http_version;
		dest.method = src.method;
		dest.url = src.url;
		dest.headers = src.headers;
		dest.conn_action = src.conn_action;
		
		//dest.body = src.body;
	}
	
	void copy_meta(const http_response & src, http_response & dest)
	{
		dest.http_version = src.http_version;
		dest.http_code = 200;
		dest.status = src.status;
		dest.headers = src.headers;
		dest.conn_action = src.conn_action;
		
		//dest.body = src.body;
	}
	
	http_body copy_mv(http_body & src)
	{
		return std::move(src);
	}
	
	http_body copy_cp(http_body & src)
	{
		return std::visit(http_body_copy_cp_visitor(), src);
	}
	
	http_body copy_chk(const http_body & src)
	{
		return std::visit(http_body_copy_chk_visitor(), src);
	}
	
	http_request copy_mv(http_request & src)
	{
		http_request dest;
		copy_meta(src, dest);
		dest.body = copy_mv(src.body);
		return dest;
	}
	
	http_request copy_cp(http_request & src)
	{
		http_request dest;
		copy_meta(src, dest);
		dest.body = copy_cp(src.body);
		return dest;
	}
	
	http_request copy_chk(const http_request & src)
	{
		http_request dest;
		copy_meta(src, dest);
		dest.body = copy_chk(src.body);
		return dest;
	}
	
	http_response copy_mv(http_response & src)
	{
		http_response dest;
		copy_meta(src, dest);
		dest.body = copy_mv(src.body);
		return dest;
	}
	
	http_response copy_cp(http_response & src)
	{
		http_response dest;
		copy_meta(src, dest);
		dest.body = copy_cp(src.body);
		return dest;
	}
	
	http_response copy_chk(const http_response & src)
	{
		http_response dest;
		copy_meta(src, dest);
		dest.body = copy_chk(src.body);
		return dest;
	}
	
	void clear(http_body & body) noexcept
	{
		return std::visit(http_body_clear_visitor(), body);
	}
	
	void clear(http_request & request) noexcept
	{
		request.http_version = 11;
		request.method.clear();
		request.url.clear();
		clear(request.body);
		request.headers.clear();
		request.conn_action = connection_action_type::def;
	}

	void clear(http_response & response) noexcept
	{
		response.http_version = 11;
		response.http_code = 404;
		response.status.clear();
		clear(response.body);
		response.headers.clear();
		response.conn_action = connection_action_type::def;
	}


	inline static std::streambuf & operator <<(std::streambuf & streambuf, char ch)
	{
		streambuf.sputc(ch);
		return streambuf;
	}

	inline static std::streambuf & operator <<(std::streambuf & streambuf, std::string_view str)
	{
		streambuf.sputn(str.data(), str.size());
		return streambuf;
	}

	static std::streambuf & operator <<(std::streambuf & streambuf, std::size_t num)
	{
		ext::itoa_buffer<decltype(num)> buffer;
		streambuf << ext::itoa(num, buffer);
		return streambuf;
	}

	static std::streambuf & operator <<(std::streambuf & streambuf, int num)
	{
		ext::itoa_buffer<decltype(num)> buffer;
		streambuf << ext::itoa(num, buffer);
		return streambuf;
	}
	
	void write_http_request(std::streambuf & os, const http_request & request, bool with_body)
	{
		os << request.method << ' ' << request.url << ' ';
		os << "HTTP/1.1\r\n";
		//os << "HTTP/" << (request.http_version / 10) << '.' << (request.http_version % 10);
		//os << '\r' << '\n';

		for (const auto & [name, value] : request.headers)
			os << name << ':' << ' ' << value << '\r' << '\n';

		if (with_body)
		{
			os << '\r' << '\n';
			os << std::visit(http_body_print_visitor(), request.body);
		}
	}

	void write_http_response(std::streambuf & os, const http_response & response, bool with_body)
	{
		os << "HTTP/1.1 " << response.http_code << ' ' << response.status << '\r' << '\n';

		for (const auto & [name, value] : response.headers)
			os << name << ':' << ' ' << value << '\r' << '\n';

		if (with_body)
		{
			os << '\r' << '\n';
			os << std::visit(http_body_print_visitor(), response.body);
		}
	}
}
