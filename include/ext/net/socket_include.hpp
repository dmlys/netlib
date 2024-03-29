﻿#pragma once
#include <boost/predef.h>
#include <ext/net/socket_fwd.hpp>

#if BOOST_OS_WINDOWS

#ifndef UNICODE
#define UNICODE
#endif // !UNICODE

#ifndef _UNICODE
#define _UNICODE
#endif // !_UNICODE

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif // !NOMINMAX

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600          // Windows Vista
#endif // !_WIN32_WINNT

#include <sdkddkver.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#else // POSIX

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>  // for socket types
#include <sys/time.h>   // for struct timeval
#include <sys/socket.h> // for socket functions
#include <sys/select.h> /* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/ioctl.h>  // for ioctl
#include <arpa/inet.h>  // for inet_ntop/inet_pton
#include <netinet/in.h> // Some systems require the inclusion of <netinet/in.h> instead of <arpa/inet.h>
#include <netdb.h>      // for getaddrinfo/freeaddrinfo

#include <netinet/in.h>
#include <netinet/tcp.h>

#if EXT_NET_USE_POLL
#include <sys/poll.h>
#endif

#endif


#ifdef EXT_ENABLE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ext/openssl.hpp>

#endif // EXT_ENABLE_OPENSSL
