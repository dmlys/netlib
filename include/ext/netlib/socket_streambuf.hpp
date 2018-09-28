#pragma once
#include <ext/netlib/socket_base.hpp>

/// для windows у нас есть реализация на winsock2
#if BOOST_OS_WINDOWS
#include <ext/netlib/winsock2_streambuf.hpp>

#ifndef EXT_WINSOCK2_SOCKET_STREAM
#define EXT_WINSOCK2_SOCKET_STREAM
#endif

namespace ext::netlib
{
	using socket_streambuf = winsock2_streambuf;
}


/// для остальных случаев откатываемся на bsd реализацию
#else  // BOOST_OS_WINDOWS
#include <ext/netlib/bsdsock_streambuf.hpp>

#ifndef EXT_BSDSOCK_SOCKET_STREAM
#define EXT_BSDSOCK_SOCKET_STREAM
#endif

namespace ext::netlib
{
	using socket_streambuf = bsdsock_streambuf;
}

#endif // BOOST_OS_WINDOWS
