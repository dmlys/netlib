#include <ext/net/http/filesystem_handler.hpp>
#include <ext/net/http/http_server_logging_helpers.hpp>

#include <ext/strings/aci_string.hpp>
#include <ext/functors/ctpred.hpp>
#include <ext/errors.hpp>


namespace ext::net::http
{
	static std::string_view trim_sep(std::string_view view) noexcept
	{
		auto first = view.data();
		auto last  = first + view.size();
		auto notsep = [](char ch) { return ch != '/'; };

		// trim left
		first = std::find_if(first, last, notsep);
		// trim right
		last = std::find_if(std::make_reverse_iterator(last), std::make_reverse_iterator(first), notsep).base();

		return std::string_view(first, last - first);
	}
	
	static std::string_view to_string(std::filesystem::file_type type)
	{
		switch (type)
		{
			using std::filesystem::file_type;
			case file_type::none:       return "none";
			case file_type::not_found:  return "not_found";
			
			case file_type::regular:    return "regular";
			case file_type::directory:  return "directory";
				
			case file_type::symlink:    return "symlink";
			case file_type::block:      return "block";
			case file_type::character:  return "character";
			case file_type::fifo:       return "fifo";
			case file_type::socket:     return "socket";
			case file_type::unknown:    return "unknown";
			default:
				EXT_UNREACHABLE();
		}
	}
	
	static std::streamsize filesize(std::filebuf & buf)
	{
		auto rpos = buf.pubseekoff(0, std::ios_base::end);
		buf.pubseekoff(0, std::ios_base::beg);
		return rpos;
	}
	
	bool filesystem_handler::accept(const ext::net::http::http_request & req, const ext::net::socket_streambuf & sock) const
	{
		ext::ctpred::equal_to<ext::aci_char_traits> eq;
		if (not eq(req.method, "get") and not eq(req.method, "headers")) return false;
		
		return req.url.compare(0, m_url_root.size(), m_url_root) == 0;
	}
	
	static auto make_response(int code, std::string status, std::string body)
	{
		http_response response;
		response.http_code = code;
		response.status = std::move(status);
		response.body = std::move(body);
		set_header(response.headers, "Content-Type", "text/plain");
		
		return response;
	}
	
	auto filesystem_handler::make_error_response(const http_request & request, const std::filesystem::path & path, std::string_view err_message) const -> http_response
	{
		return make_response(500, "INTERNAL SERVER ERROR", std::string(err_message));
	}
	
	auto filesystem_handler::make_error_response(const http_request & request, const std::filesystem::path & path, const std::exception & ex) const -> http_response
	{
		LOG_ERROR("ECXEPTION");
		return make_response(500, "INTERNAL SERVER ERROR", "Internal Server Error");
	}
	
	auto filesystem_handler::make_error_response(const http_request & request, const std::filesystem::path & path, std::error_code errc) const -> http_response
	{
		return make_response(500, "INTERNAL SERVER ERROR", "Internal Server Error");
	}
	
	auto filesystem_handler::make_notfound_response(const http_request & request, const std::filesystem::path & path) const -> http_response
	{
		return make_response(404, "NOT FOUND", "Not found");
	}
	
	auto filesystem_handler::make_forbidden_response(const http_request & request, const std::filesystem::path & path) const -> http_response
	{
		return make_notfound_response(request, path);
	}
	
	auto filesystem_handler::make_file_response(const http_request & request, const std::filesystem::path & path, std::filebuf & fb) const -> http_response
	{
		ext::ctpred::equal_to<ext::aci_char_traits> eq;
		ext::net::http::http_response response;
		
		response.http_code = 200;
		response.status = "OK";
		
		auto fsize = filesize(fb);
		set_header(response.headers, "Content-Length", std::to_string(fsize));
		
		if (eq(request.method, "headers"))
		{
			response.body = ext::net::http::null_body;
			LOG_DEBUG("Prepared HEADERS response of file stream size = {}", fsize);
		}
		else
		{
			ext::net::http::lstream body;
			body.size = fsize;
			body.stream = std::make_unique<std::filebuf>(std::move(fb));
			response.body = std::move(body);
			
			LOG_DEBUG("Prepared response with file stream of size = {}", fsize);
		}
		
		return response;
	}
	
	auto filesystem_handler::make_directory_response(const http_request & request, const std::filesystem::path & path, std::filebuf & fb) const -> http_response
	{
		return make_notfound_response(request, path);
	}
	
	auto filesystem_handler::make_special_response(const http_request & request, const std::filesystem::path & path, std::filesystem::file_status stat, std::filebuf & fb) const -> http_response
	{
		return make_notfound_response(request, path);
	}
	
	auto filesystem_handler::serve_request(const ext::net::http::http_request & request, const std::filesystem::path & path) const -> ext::net::http_response
	{
		std::error_code ec;
		std::filebuf fb;
		if (fb.open(path.c_str(), std::ios::in | std::ios::binary))
		{
			auto fstat = std::filesystem::status(path, ec);
			LOG_INFO("Opened path = {}, fstat.type = {}", path, to_string(fstat.type()));
			
			switch (fstat.type())
			{
				using std::filesystem::file_type;
				case file_type::none:       return make_error_response(request, path, ec);
				case file_type::not_found:  return make_notfound_response(request, path);
				
				case file_type::regular:    return make_file_response(request, path, fb);
				case file_type::directory:  return make_directory_response(request, path, fb);
					
				case file_type::symlink:
				case file_type::block:
				case file_type::character:
				case file_type::fifo:
				case file_type::socket:
				case file_type::unknown:
				default:
					return make_special_response(request, path, fstat, fb);
			}
		}
		else
		{
			auto errc = errno;
			LOG_INFO("Failed to open path = {}, errc = {}", path, ext::format_errno(errc));
			
			switch (errc)
			{
				case EACCES: return   make_forbidden_response(request, path);
				case ENOENT: return   make_notfound_response(request, path);
				
				//case EMFILE:
				//case ENFILE:
				//case ENAMETOOLONG:
				default:
					return make_error_response(request, path, std::error_code(errc, std::generic_category()));
			}
		}
	}
	
	auto filesystem_handler::process(ext::net::http::http_request & request) const -> result_type
	{
		LOG_INFO("Processing filesystem_handler request, url = {}", request.url);
		
		std::filesystem::path path = m_filesystem_root;
		std::string_view fname = request.url;
		fname = trim_sep(fname.substr(m_url_root.size()));
		path /= fname;
		
		return serve_request(request, path);
	}

	filesystem_handler::filesystem_handler(std::string url_root, std::string filesystem_root)
		: m_url_root(std::move(url_root)), m_filesystem_root(std::move(filesystem_root))
	{
		
	}
}
