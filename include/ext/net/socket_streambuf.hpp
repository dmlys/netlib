#pragma once
#include <ext/net/socket_base.hpp>

/// для windows у нас есть реализация на winsock2
#if BOOST_OS_WINDOWS
#include <ext/net/winsock2_streambuf.hpp>

#ifndef EXT_WINSOCK2_SOCKET_STREAM
#define EXT_WINSOCK2_SOCKET_STREAM
#endif

namespace ext::net
{
	using socket_streambuf = winsock2_streambuf;
}


/// для остальных случаев откатываемся на bsd реализацию
#else  // BOOST_OS_WINDOWS
#include <ext/net/bsdsock_streambuf.hpp>

#ifndef EXT_BSDSOCK_SOCKET_STREAM
#define EXT_BSDSOCK_SOCKET_STREAM
#endif

namespace ext::net
{
	using socket_streambuf = bsdsock_streambuf;
}

#endif // BOOST_OS_WINDOWS
