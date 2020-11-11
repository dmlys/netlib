#pragma once
#include <ostream>
#include <algorithm>
#include <variant>
#include <vector>
#include <string>
#include <string_view>
#include <unordered_map>

//#include <boost/iterator/filter_iterator.hpp>
#include <boost/range.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <ext/range/range_traits.hpp>

#include <ext/future.hpp>
#include <ext/iostreams/streambuf.hpp>

namespace ext::net::http
{
	struct http_header;
	struct http_header_view;

	struct http_header_view
	{
		std::string_view name;
		std::string_view value;

		operator http_header() const;
		operator bool() const noexcept { return not name.empty(); }
	};

	struct http_header
	{
		std::string name;
		std::string value;

		operator http_header_view() const noexcept;
		operator bool() const noexcept { return not name.empty(); }
	};

	using http_headers_vector = std::vector<http_header>;
	using http_headers_view_vector = std::vector<http_header_view>;


	/// what should be done with connection: close, keep-alive, or some default action
	enum class connection_action_type : unsigned
	{
		/// default(def): close or keep_alive, which can be choosed based on some heuristics.
		/// For http_server that can mean choose response action based on request action.
		def = 0,
		close = 1,
		keep_alive = 2,
	};

	enum class http_body_type : unsigned
	{
		            // http request/response body holds:
		string = 0, //  * std::string
		vector = 1, //  * std::vector
		stream = 2, //  * http_body_streambuf
		async  = 3, //  * async_http_body_source
		null   = 4, //  * no body required/produced, represented as nullbody
	};

	/// special type representing null body, std::nullopt probably can be used instead, but we use it already for "no response at all",
	/// to make things less ambiguous we use different type.
	struct null_body_type {} constexpr null_body;
	
	
	/// Exception thrown from http_body_streambuf and async_http_body_source, when http_server is stopped, and read operation is called.
	/// See http_body_streambuf, async_http_body_source description
	class closed_exception : public std::runtime_error
	{
	public:
		using std::runtime_error::runtime_error;
	};
	
	/// Interface for closable http_body types(http_body_streambuf, async_http_body_source). Used mainly by http_server.
	/// 
	/// Lifetime and close method:
	///  http_body_streambuf, async_http_body_source and alike classes can be bound to some parent object, in case of request - http_server.
	///  Life time of parent object should not linger on those classes, yet it can require some resources from it.
	///
	///  Thats what for close method is: whenever parent object can no longer/don't want to serve child objects
	///  like http_body_streambuf, async_http_body_source - it should close them via close method, severing any connections with those objects.
	///
	///  Implementation of close should interrupt any current blocking operations and change state of this class to interrupted -
	///  current and any new requests for data should report error via closed_exception.
	///
	///  Close method returns ext::future - it will become ready when interruption is finished, through interrupting should not take/block long.
	///  Also close probably should not throw runtime_errors(or any other errors except very fatal, like out of memory).
	///  NOTE: This method should be called only once by parent object(and not called at all by anyone else, TODO: remove this restriction).
	class closable_http_body
	{
	public:
		virtual ext::future<void> close() = 0;
		virtual ~closable_http_body() = default;
	};
	
	/// http body streambuf, internally reads from socket and parses, reading is done in blocking maner.
	/// Read operations can throw, also NOTE that if you place this streambuf into istream - it will catch and eat exceptions.
	/// See also closable_http_body
	class http_body_streambuf : public ext::streambuf /* optionally can also implement closable_http_body */
	{
	public:
		/// just a destructor
		virtual ~http_body_streambuf() = default;
	};

	/// Async http body source. This is both for http request body and http response body.
	/// This interface used both for http requests and response, http_server and some other abstract http handlers.
	///
	///
	/// read_some - async reading data method:
	///  New data is returned via read_some method via ext::future object:
	///   In case of http response - source is abstract: just some internal buffer, or some iterational calculation, or even another socket.
	///   In case of http request - data is lazily read and parsed from socket, data is returned through future object.
	///    Internally this class reads and parses data from associated socket, reading is done non blockingly.
	///    if no data available - socket would be submited for waiting into internal socket queue.
	///    in case of errors - exception will transfered through returned future.
	///
	///  NOTE: read_some should only be called once per iteration, call read_some -> get some result -> call it again.
	///        concurrent calls	to read_some(from same/different thread) - is a error.
	/// See also closable_http_body
	class async_http_body_source /* optionally can also implement closable_http_body */
	{
	public:
		/// std::nullopt -> http body end. 
		/// chunks of 0 size are allowed, but they will be skipped for Transfer-Encoding: chunked, because chunk of 0 size means end. 
		using chunk_type = std::optional<std::vector<char>>;
		
		/// prepares/generates some data, writes into buffer and returns it, in case of errors returns future with exception.
		/// Overall any exception can be thrown, http_server will throw std::runtime_error/std::system_error through.
		/// 
		/// size - a hint of what size should result chunk be, implementation can ignore it.
		///  0 - means no hint, and implementation should choose size.
		///  http_server does tries to return chunk of asked size,
		///  0 - means return whatever available in a socket(bounded by some implementation defined max size)
		virtual auto read_some(std::vector<char> buffer, std::size_t size = 0) -> ext::future<chunk_type> = 0;

	public:
		/// just a destructor
		virtual ~async_http_body_source() = default;
	};


	using http_body = std::variant<
		std::string,
		std::vector<char>,
		std::unique_ptr<std::streambuf>,
		std::unique_ptr<async_http_body_source>,
		null_body_type
	>;

	struct http_request
	{
		int http_version = 11;
		std::string method;
		std::string url;
		http_body   body;
		http_headers_vector headers;

		connection_action_type conn_action = connection_action_type::def;
	};

	struct http_response
	{
		int http_version = 11;
		int http_code = 200;
		std::string status;
		http_body   body;
		http_headers_vector headers;

		connection_action_type conn_action = connection_action_type::def;
	};

	std::optional<std::size_t> size(const http_body & body) noexcept;
	template <class Container> void copy(const http_body & body, Container & cont);
	template <class Container> void copy(const Container & cont, http_body & body);

	void clear(http_body     & body)    noexcept;
	void clear(http_request  & request) noexcept;
	void clear(http_response & request) noexcept;
	
	void write_http_request (std::streambuf & os, const http_request  & request,  bool with_body = true);
	void write_http_response(std::streambuf & os, const http_response & response, bool with_body = true);

	inline void write_http_request (std::ostream & os, const http_request  & request,  bool with_body = true) { return write_http_request(*os.rdbuf(), request, with_body);   }
	inline void write_http_response(std::ostream & os, const http_response & response, bool with_body = true) { return write_http_response(*os.rdbuf(), response, with_body); }

	inline std::ostream & operator <<(std::ostream & os, const http_request  & request)  { write_http_request(os, request);   return os; }
	inline std::ostream & operator <<(std::ostream & os, const http_response & response) { write_http_response(os, response); return os; }

	/************************************************************************/
	/*                   header manipulation functions                      */
	/************************************************************************/
	
	template <class HeaderRange>
	auto get_header_value(const HeaderRange & headers, std::string_view name) noexcept -> std::string_view;
	
	template <class HeaderRange> 
	auto find_header(HeaderRange & headers, std::string_view name) noexcept -> http_header *;
	
	template <class HeaderRange> auto get_header(const HeaderRange & headers, std::string_view name) noexcept -> http_header_view;
	template <class HeaderRange> void set_header(HeaderRange & headers, std::string_view name, std::string_view value);
	
	template <class HeaderRange> void set_header(HeaderRange & headers, http_header header);
	template <class HeaderRange> auto get_headers(const HeaderRange & headers, std::string_view name) noexcept; // -> http_headers_view_vector
	
	template <class HeaderRange> void remove_header(HeaderRange & headers, std::string_view name) noexcept;
	template <class HeaderRange> void add_header(HeaderRange & headers, std::string_view name, std::string_view value);
	template <class HeaderRange> void add_header(HeaderRange & headers, http_header header);

	template <class HeaderRange> void prepend_header_list_value(HeaderRange & headers, std::string_view name, std::string_view value);
	template <class HeaderRange> void append_header_list_value(HeaderRange & headers, std::string_view name, std::string_view value);
	
	
	template <class HeaderRange1, class HeaderRange2>
	void copy_header(const HeaderRange1 & source_headers, HeaderRange2 & dest_headers, std::string_view name);
	
	template <class HeaderRange1, class HeaderRange2>
	void copy_headers(HeaderRange1 & dest_headers, const HeaderRange2 & source_headers, std::string_view name);
	
	
	
	
	
	/************************************************************************/
	/*                   template functions implementation                  */
	/************************************************************************/

	template <class Container>
	struct http_body_copy_from_visitor
	{
		Container * cont;
		http_body_copy_from_visitor(Container & cont) : cont(&cont) {}
		
		void operator()(const std::string       & str ) const { cont->assign(str.begin(), str.end()); }
		void operator()(const std::vector<char> & data) const { cont->assign(data.begin(), data.end()); }
		void operator()(const std::unique_ptr<std::streambuf> & ) const { throw std::runtime_error("Can't copy from http_body:std::streambuf"); }
		void operator()(const std::unique_ptr<async_http_body_source> & ) const { throw std::runtime_error("Can't copy from http_body:std::streambuf"); }
		void operator()(const null_body_type) const { cont->clear(); }
	};
	
	template <class Container>
	struct http_body_copy_to_visitor
	{
		const Container * cont;
		http_body_copy_to_visitor(const Container & cont) : cont(&cont) {}
		
		void operator()(std::string       & str ) const { str.assign(cont->begin(), cont->end()); }
		void operator()(std::vector<char> & data) const { data.assign(cont->begin(), cont->end()); }
		void operator()(std::unique_ptr<std::streambuf> & ) const { throw std::runtime_error("Can't copy into http_body:std::streambuf"); }
		void operator()(std::unique_ptr<async_http_body_source> & ) const { throw std::runtime_error("Can't copy into http_body:async_http_body_source"); }
		void operator()(null_body_type) const { throw std::runtime_error("Can't copy into http_body/null_body_type"); }
	};
	
	template <class Container>
	inline void copy(const http_body & body, Container & cont)
	{
		std::visit(http_body_copy_from_visitor(cont), body);
	}
	
	template <class Container>
	inline void copy(const Container & cont, http_body & body)
	{
		std::visit(http_body_copy_to_visitor(cont), body);
	}
	
	
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

	template <class HeaderRange>
	inline void set_header(HeaderRange & headers, http_header header)
	{
		return set_header(headers, header.name, header.value);
	}

	template <class HeaderRange>
	inline auto get_headers(const HeaderRange & headers, std::string_view name) noexcept // -> http_headers_view_vector
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
	inline void add_header(HeaderRange & headers, http_header header)
	{
		headers.push_back(std::move(header));
	}

	template <class HeaderRange>
	void prepend_header_list_value(HeaderRange & headers, std::string_view name, std::string_view value)
	{
		auto * header = find_header(headers, name);
		if (not header) return set_header(headers, name, value);
		
		std::string & hdr_val = header->value;
		auto pos = hdr_val.find_first_not_of(' ');
		if (pos == hdr_val.npos)
		{
			hdr_val = value;
			return;
		};
		
		if (hdr_val[pos] == ',')
		{
			hdr_val.insert(0, value);
		}
		else
		{
			hdr_val.insert(0, value.size() + 2, ' ');
			hdr_val.replace(0, value.size(), value);
			hdr_val.replace(value.size(), 2, ", ");
		}
	}
	
	template <class HeaderRange>
	void append_header_list_value(HeaderRange & headers, std::string_view name, std::string_view value)
	{
		auto * header = find_header(headers, name);
		if (not header) return set_header(headers, name, value);
		
		std::string & hdr_val = header->value;
		auto pos = hdr_val.find_last_not_of(' ');
		if (pos == hdr_val.npos)
		{
			hdr_val = value;
			return;
		};
		
		if (hdr_val[pos] != ',')
			++pos;
		
		hdr_val.replace(pos, 2, ", ");
		hdr_val.replace(pos + 2, std::string::npos, value);
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
}

namespace ext::net
{
	using http::http_request;
	using http::http_response;
}
