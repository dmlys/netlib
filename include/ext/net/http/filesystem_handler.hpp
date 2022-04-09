#pragma once
#include <string>
#include <string_view>
#include <fstream>
#include <filesystem>

#include <ext/net/http/http_server_handler.hpp>

namespace ext::net::http
{
	class filesystem_handler : public ext::net::http::http_server_handler
	{
		std::string m_url_root;
		std::string m_filesystem_root;
		
	protected:
		virtual auto make_error_response(const http_request & request, const std::filesystem::path & path, std::string_view err_message) const -> http_response;
		virtual auto make_error_response(const http_request & request, const std::filesystem::path & path, const std::exception & ex) const -> http_response;
		virtual auto make_error_response(const http_request & request, const std::filesystem::path & path, std::error_code errc) const -> http_response;
		
		virtual auto make_notfound_response(const http_request & request, const std::filesystem::path & path) const -> http_response;
		virtual auto make_forbidden_response(const http_request & request, const std::filesystem::path & path) const -> http_response;
		
		//virtual auto make_path_response(const http_request & request, const std::filesystem::path & path) const -> http_response;
		
		virtual auto make_file_response(const http_request & request, const std::filesystem::path & path, std::filebuf & fb) const -> http_response;
		virtual auto make_directory_response(const http_request & request, const std::filesystem::path & path, std::filebuf & fb) const -> http_response;
		virtual auto make_special_response(const http_request & request, const std::filesystem::path & path, std::filesystem::file_status stat, std::filebuf & fb) const -> http_response;
		
	public:
		virtual auto wanted_body_type(http_server_control & control) const noexcept -> ext::net::http::http_body_type override { return ext::net::http::http_body_type::null; }
		virtual bool accept(http_server_control & control) const override;
		virtual result_type process(http_server_control & control) const override;
		virtual auto serve_request(const ext::net::http::http_request & req, const std::filesystem::path & path) const -> ext::net::http_response;
		
	public:
		filesystem_handler(std::string url_root, std::string filesystem_root);
		~filesystem_handler() = default;		
	};
}
