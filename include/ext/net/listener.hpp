#pragma once
#include <memory>
#include <string>
#include <stdexcept>

#include <ext/net/socket_base.hpp>
#include <ext/net/socket_stream.hpp>

namespace ext::net
{
	/// exception thrown by listen and bind operations of ext::net::listener
	class listener_exception : public std::system_error
	{
	protected:
		std::string m_sock_endpoint;

	public:
		listener_exception(std::string sock_endpoint, std::error_code errc, std::string msg);

	public:
		const std::string & sock_endpoint() const noexcept { return m_sock_endpoint; }
		      std::string & sock_endpoint()       noexcept { return m_sock_endpoint; }
	};


	/// simple socket listener class for use in very simple socket server applications,
	/// for more complex ones - use more appropriate libraries, for example boost::asio
	class listener
	{	
	private:
		socket_handle_type m_listening_socket = -1;

	public:
		/// check if socket is listen state(listen method was called),
		/// internally calls ::getsockopt(..., SOL_SOCKET SO_ACCEPTCONN, ...).
		/// Throws std::system_error in case or errors
		bool is_listening() const;
		bool is_socket() const;
		explicit operator bool() const { return is_socket(); }

		/// underlying socket handle
		socket_handle_type handle() const noexcept { return m_listening_socket; }

	public:
		static const int af_unspec; // = AF_UNSPEC
		static const int af_inet;   // = AF_INET
		static const int af_inet6;  // = AF_INET6

	public:
		/// calls ::getsockname(handle(), addr, namelen),
		/// throws std::system_error in case or errors
		void getsockname(sockaddr_type * addr, socklen_t * addrlen) const;
		/// returns socket endpoint address port as $addr:$port string(calls getsockname)
		/// throws std::system_error in case or errors
		std::string sock_endpoint() const;
		/// returns socket endpoint address and port(calls getsockname).
		/// throws std::system_error in case or errors
		void sock_name(std::string & name, unsigned short & port) const;
		auto sock_name() const -> std::pair<std::string, unsigned short>;
		/// returns socket endpoint address(calls getsockname).
		/// throws std::system_error in case or errors
		std::string sock_address() const;
		/// returns socket endpoint port(calls getsockname).
		/// throws std::system_error in case or errors
		unsigned short sock_port() const;

	public:
		/// binds this listener to given address and port.
		/// first address is resolved via ::getaddrinfo with hints:
		///    hint.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_V4MAPPED | AI_ALL;
		///    hint.ai_family = af;
		///    hint.ai_protocol = IPPROTO_TCP;
		///    hint.ai_socktype = SOCK_STREAM;
		/// then socket from created and bound from/to resolved address.
		/// Also setsockopt with SO_REUSEADDR is called.
		/// Throws std::system_error in case or errors
		void bind(unsigned short port, int af = af_unspec) { bind("", port, af); }
		void bind(std::string ipaddr, unsigned short port, int af = af_unspec);
		/// calls ::listen and checks result,
		/// throws std::system_error in case or errors
		void listen(int backlog);
		/// calls ::accept and checks result,
		/// throws std::system_error in case or errors
		socket_streambuf accept();
		/// calls ::shutdown and checks result,
		/// throws std::system_error in case or errors
		void shutdown();
		/// calls ::close and checks result,
		/// throws std::system_error in case or errors
		void close();

	public:
		listener() = default;
		~listener();

		listener(unsigned short port, int af = af_unspec) { bind(port, af); }
		listener(std::string ipaddr, unsigned short port, int af = af_unspec) { bind(std::move(ipaddr), port, af); }

		listener(listener && l) noexcept;
		listener & operator =(listener &&) noexcept;

		listener(const listener &) = delete;
		listener & operator =(const listener &) = delete;

		friend void swap(listener & l1, listener & l2) noexcept;
	};
}
