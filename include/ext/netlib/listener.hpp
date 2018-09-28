#pragma once
#include <memory>
#include <string>
#include <ext/netlib/socket_base.hpp>
#include <ext/netlib/socket_stream.hpp>

namespace ext::netlib
{
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
		explicit operator bool() const { return is_listening(); }

		/// underlying socket handle
		socket_handle_type handle() const noexcept { return m_listening_socket; }

	public:
		/// calls ::getsockname(handle(), addr, namelen),
		/// throws std::system_error in case or errors
		void getsockname(sockaddr_type * addr, socklen_t * addrlen);
		/// returns socket endpoint address port as $addr:$port string(calls getsockname)
		/// throws std::system_error in case or errors
		std::string sock_endpoint();
		/// returns socket endpoint address and port(calls getsockname).
		/// throws std::system_error in case or errors
		void sock_name(std::string & name, unsigned short & port);
		auto sock_name() -> std::pair<std::string, unsigned short>;
		/// returns socket endpoint address(calls getsockname).
		/// throws std::system_error in case or errors
		std::string sock_address();
		/// returns socket endpoint port(calls getsockname).
		/// throws std::system_error in case or errors
		unsigned short sock_port();

	public:
		/// binds this listener to given address and port.
		/// first address is resolved via ::getaddrinfo with hints:
		///    hint.ai_flags = AI_PASSIVE | AI_V4MAPPED | AI_ADDRCONFIG | AI_ALL;
		///    hint.ai_family = AF_UNSPEC;
		///    hint.ai_protocol = IPPROTO_TCP;
		///    hint.ai_socktype = SOCK_STREAM;
		/// then socket from created and bound from/to resolved address.
		/// Also setsockopt with SO_REUSEADDR is called.
		/// Throws std::system_error in case or errors
		void bind(unsigned short port) { bind("", port); }
		void bind(std::string ipaddr, unsigned short port);
		/// calls ::listen and checks result,
		/// throws std::system_error in case or errors
		void listen(int backlog = 1);
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

		listener(listener && l) noexcept;
		listener & operator =(listener &&) noexcept;

		listener(const listener &) = delete;
		listener & operator =(const listener &) = delete;

		friend void swap(listener & l1, listener & l2) noexcept;
	};
}
