#pragma once
#include <ostream>
#include <algorithm>
#include <vector>
#include <string>
#include <string_view>
#include <unordered_map>

//#include <boost/iterator/filter_iterator.hpp>
#include <boost/range.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <ext/range/range_traits.hpp>

namespace ext::net::http
{
	struct http_header;
	struct http_header_view;

	struct http_header_view
	{
		std::string_view name;
		std::string_view value;

		operator http_header() const;
		operator bool() const noexcept { return name.empty(); }
	};

	struct http_header
	{
		std::string name;
		std::string value;

		operator http_header_view () const noexcept;
		operator bool() const noexcept { return name.empty(); }
	};

	using http_headers_vector = std::vector<http_header>;
	using http_headers_view_vector = std::vector<http_header_view>;


	/// what should be done with connection: close, keep-alive, or some default action
	enum connection_action_type : unsigned
	{
		/// default(def): close or keep_alive, which can be choosed based on some heuristics.
		/// For http_server that can mean choose response action based on request action.
		def = 0,
		close = 1,
		keep_alive = 2,
	};

	struct http_request
	{
		int http_version = 11;
		std::string method;
		std::string url;
		std::string body;
		http_headers_vector headers;

		connection_action_type conn_action = def;
	};

	struct http_response
	{
		int http_version;
		int http_code;
		std::string status;
		std::string body;
		http_headers_vector headers;

		connection_action_type conn_action = def;
	};


	template <class HeaderRange>
	auto get_header_value(const HeaderRange & headers, std::string_view name) noexcept -> std::string_view
	{
		for (auto & header : headers)
		{
			if (header.name == name)
				return header.value;
		}

		return "";
	}

	//template <class HeaderRange>
	//auto find_header(const HeaderRange & headers, std::string_view name) noexcept -> const http_header *
	//{
	//	for (auto & header : headers)
	//	{
	//		if (header.name == name)
	//			return &header;
	//	}
	//
	//	return nullptr;
	//}

	template <class HeaderRange>
	auto find_header(HeaderRange & headers, std::string_view name) noexcept -> http_header *
	{
		for (auto & header : headers)
		{
			if (header.name == name)
				return &header;
		}

		return nullptr;
	}

	template <class HeaderRange>
	auto get_header(const HeaderRange & headers, std::string_view name) noexcept -> http_header_view
	{
		for (auto & header : headers)
		{
			if (header.name == name)
				return header;
		}

		return {};
	}

	template <class HeaderRange>
	void set_header(HeaderRange & headers, std::string_view name, std::string_view value)
	{
		for (auto & header : headers)
		{
			if (header.name == name)
			{
				header.value = value;
				return;
			}
		}

		headers.emplace_back();
		auto & header = headers.back();
		header.name = name;
		header.value = value;
	}

	template <class HeaderRange> void set_header(HeaderRange & headers, http_header header)
	{
		return set_header(headers, header.name, header.value);
	}

	template <class HeaderRange>
	auto get_headers(const HeaderRange & headers, std::string_view name) noexcept // -> http_headers_view_vector
	{
		auto filter = [name](auto & header) { return header.name == name; };
		return boost::adaptors::filter(headers, filter);

		//http_headers_view_vector result;
		//for (auto & header : headers)
		//{
		//	if (header.name == name)
		//		result.push_back(header);
		//}
		//
		//return result;
	}

	template <class HeaderRange>
	void remove_header(HeaderRange & headers, std::string_view name) noexcept
	{
		auto first = headers.begin();
		auto last  = headers.end();

		headers.erase(
			std::remove_if(first, last, [name](auto & hdr) { return hdr.name == name; }),
			last
		);
	}

	template <class HeaderRange>
	void add_header(HeaderRange & headers, std::string_view name, std::string_view value)
	{
		headers.emplace_back();

		auto & header = headers.back();
		header.name = name;
		header.value = value;
	}

	template <class HeaderRange>
	void add_header(HeaderRange & headers, http_header header)
	{
		headers.push_back(std::move(header));
	}

	template <class HeaderRange1, class HeaderRange2>
	void copy_header(const HeaderRange1 & source_headers, HeaderRange2 & dest_headers, std::string_view name)
	{
		auto val = get_header_value(source_headers, name);
		set_header(dest_headers, name, val);
	}

	template <class HeaderRange1, class HeaderRange2>
	void copy_headers(HeaderRange1 & dest_headers, const HeaderRange2 & source_headers, std::string_view name)
	{
		remove_header(dest_headers, name);

		for (auto & hdr : get_headers(source_headers, name))
		{
			dest_headers.emplace_back();
			auto & newhdr = dest_headers.back();
			newhdr.name  = hdr.name;
			newhdr.value = hdr.value;
		}
	}


	void write_http_request (std::streambuf & os, const http_request  & request,  bool with_body = true);
	void write_http_response(std::streambuf & os, const http_response & response, bool with_body = true);

	inline void write_http_request (std::ostream & os, const http_request  & request,  bool with_body = true) { return write_http_request(*os.rdbuf(), request, with_body);   }
	inline void write_http_response(std::ostream & os, const http_response & response, bool with_body = true) { return write_http_response(*os.rdbuf(), response, with_body); }

	inline std::ostream & operator <<(std::ostream & os, const http_request  & request)  { write_http_request(os, request);   return os; }
	inline std::ostream & operator <<(std::ostream & os, const http_response & response) { write_http_response(os, response); return os; }
}

namespace ext::net
{
	using http::http_request;
	using http::http_response;
}
