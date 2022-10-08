#pragma once
#include <memory>
#include <string>
#include <stdexcept>

#include <ext/net/socket_base.hpp>

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


	/// simple socket listener wrapper class
	class listener
	{
	private:
		socket_handle_type m_listening_socket = -1;

	public:
		// free functions for direct calls on listener handle
		
		/// check if socket is listen state(listen method was called),
		/// internally calls ::getsockopt(..., SOL_SOCKET SO_ACCEPTCONN, ...).
		/// Throws std::system_error in case or errors
		static bool is_listening(socket_handle_type handle);
		static bool is_socket(socket_handle_type handle);
		
		/// binds this listener to given address and port.
		/// first address is resolved via ::getaddrinfo with hints:
		///    hint.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_V4MAPPED | AI_ALL;
		///    hint.ai_family = af;
		///    hint.ai_protocol = IPPROTO_TCP;
		///    hint.ai_socktype = SOCK_STREAM;
		/// then socket from created and bound from/to resolved address.
		/// Also setsockopt with SO_REUSEADDR is called.
		/// Throws std::system_error in case or errors
		static void bind(socket_handle_type & handle, const char * ipaddr, unsigned short port, int af = af_unspec);
		/// binds this listener to given address, protocol and family is taken from address
		static void bind(socket_handle_type & handle, sockaddr * sockaddr, socklen_t addrlen, int socktype, int protocol = 0);
		
		static void bind(socket_handle_type & handle, unsigned short port, int af = af_unspec) { return bind(handle, nullptr, port, af); }
		static void bind(socket_handle_type & handle, const std::string & ipaddr, unsigned short port, int af = af_unspec)
			{ return bind(handle, ipaddr.empty() ? nullptr : ipaddr.c_str(), port, af); }
		
		/// calls ::listen and checks result,
		/// throws std::system_error in case or errors
		static void listen(socket_handle_type handle, int backlog);
		/// calls ::accept and checks result,
		/// throws std::system_error in case or errors
		static socket_handle_type accept(socket_handle_type handle);
		/// calls ::shutdown and checks result,
		/// throws std::system_error in case or errors
		static void shutdown(socket_handle_type handle);
		
		// getsockname family functions are availible from socket_base.hpp
		
	public:
		/// check if socket is listen state(listen method was called),
		/// internally calls ::getsockopt(..., SOL_SOCKET SO_ACCEPTCONN, ...).
		/// Throws std::system_error in case or errors
		bool is_listening() const { return is_listening(m_listening_socket); }
		bool is_socket() const { return is_socket(m_listening_socket); }
		explicit operator bool() const { return is_socket(); }

		/// underlying socket handle
		socket_handle_type handle() const noexcept { return m_listening_socket; }
		socket_handle_type release()      noexcept { return std::exchange(m_listening_socket, invalid_socket); }

	public:
		/// calls ::getsockname(handle(), addr, namelen),
		/// throws std::system_error in case or errors
		void getsockname(sockaddr_type * addr, socklen_t * addrlen) const { return ext::net::getsockname(m_listening_socket, addr, addrlen); }
		/// returns socket endpoint address port as $addr:$port string(calls getsockname)
		/// throws std::system_error in case or errors
		std::string sock_endpoint() const { return ext::net::sock_endpoint(m_listening_socket); }
		/// safe version of sock_endpoint - does not throws exception(except for std::bad_alloc),
		/// in case of error returns <ERR:code>. For example - <ENOTCONN:107>
		std::string sock_endpoint_noexcept() const { return ext::net::sock_endpoint_noexcept(m_listening_socket); }
		/// returns socket endpoint address and port(calls getsockname).
		/// throws std::system_error in case or errors
		void sock_name(std::string & name, unsigned short & port) const  { return ext::net::sock_name(m_listening_socket, name, port); }
		auto sock_name() const -> std::pair<std::string, unsigned short> { return ext::net::sock_name(m_listening_socket); }
		/// returns socket endpoint address(calls getsockname).
		/// throws std::system_error in case or errors
		std::string sock_address() const { return ext::net::sock_address(m_listening_socket); }
		/// returns socket endpoint port(calls getsockname).
		/// throws std::system_error in case or errors
		unsigned short sock_port() const { return ext::net::sock_port(m_listening_socket); }

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
		void bind(const char * ipaddr, unsigned short port, int af = af_unspec)           { return bind(m_listening_socket, ipaddr, port, af); }
		/// binds this listener to given address, protocol and family is taken from address
		void bind(sockaddr * sockaddr, socklen_t addrlen, int socktype, int protocol = 0) { return bind(m_listening_socket, sockaddr, addrlen, socktype, protocol); }
		
		void bind(unsigned short port, int af = af_unspec)                                { return bind(m_listening_socket, port, af); }
		void bind(const std::string & ipaddr, unsigned short port, int af = af_unspec)    { return bind(m_listening_socket, ipaddr, port, af); }
		
		/// calls ::listen and checks result,
		/// throws std::system_error in case or errors
		void listen(int backlog) { return listen(m_listening_socket, backlog); }
		/// calls ::accept and checks result,
		/// throws std::system_error in case or errors
		socket_handle_type accept() { return accept(m_listening_socket); }
		/// calls ::shutdown and checks result,
		/// throws std::system_error in case or errors
		void shutdown();
		/// calls ::close and checks result,
		/// throws std::system_error in case or errors
		void close() noexcept;

	public:
		listener() = default;
		~listener();

		listener(ext::net::handle_arg_type, socket_handle_type handle) : m_listening_socket(handle) {}
		listener(unsigned short port, int af = af_unspec) { bind(port, af); }
		listener(std::string ipaddr, unsigned short port, int af = af_unspec) { bind(std::move(ipaddr), port, af); }

		listener(listener && l) noexcept;
		listener & operator =(listener &&) noexcept;

		listener(const listener &) = delete;
		listener & operator =(const listener &) = delete;

		friend void swap(listener & l1, listener & l2) noexcept;
	};
}
