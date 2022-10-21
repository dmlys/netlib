#pragma once
// author: Dmitry Lysachenko
// date: Tuesday 17 May 2016
// license: boost software license
//          http://www.boost.org/LICENSE_1_0.txt
//

#include <cstdint>
#include <boost/predef.h>

/// Depending on platform some typedefs can be different,
/// signatures of functions can be different and so on.
/// Including system files can be somewhat bloating(especially windows) - instead forward them here
///
/// this file should forward declare:
/// * in_addr, in6_addr, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage
/// * addrinfo
/// * timeval
/// * socket_handle_type
/// * socklen_t
/// * sockoptlen_t - type that setsockopt accepts as len parameter,
///                  normally it should same as socklen_t but on some platforms can be different
///

#if   BOOST_OS_WINDOWS

	struct in_addr;
	struct in6_addr;
	struct sockaddr;
	struct sockaddr_in;
	struct sockaddr_in6;
	struct sockaddr_storage;
	
	struct addrinfo;
	struct addrinfoW;

	struct timeval;

	typedef std::uintptr_t   socket_handle_type;
	typedef int              socklen_t;
	typedef socklen_t        sockoptlen_t;

	#if _WIN32_WINNT >= 0x0600 // Starting from Windows Vista WSAPoll is availiable
	#define EXT_NET_POLL_AVAILIABLE 1
	#else
	#define EXT_NET_POLL_AVAILIABLE 0
	#endif

#elif BOOST_OS_CYGWIN

	struct in_addr;
	struct in6_addr;
	struct sockaddr;
	struct sockaddr_in;
	struct sockaddr_in6;
	struct sockaddr_storage;
	
	struct addrinfo;
	struct addrinfoW;
	
	struct timeval;

	typedef int              socket_handle_type;
	typedef int              socklen_t;
	typedef socklen_t        sockoptlen_t;

	#define EXT_NET_POLL_AVAILIABLE 0

#elif BOOST_OS_HPUX

	// hp-ux have 2 net libraries, standard libc and libxnet
	struct in_addr;
	struct in6_addr;
	struct sockaddr;
	struct sockaddr_in;
	struct sockaddr_in6;
	struct sockaddr_storage;
	
	struct addrinfo;
	struct addrinfoW;
	
	struct timeval;

	typedef int              socket_handle_type;
	typedef std::size_t      socklen_t;

	// if defined _XOPEN_SOURCE - it's libxnet, you probably also should link with -lxnet
	#if defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE >= 500 || defined(_XOPEN_SOURCE_EXTENDED))
	    typedef socklen_t    sockoptlen_t;
	#else
	    typedef int          sockoptlen_t;
	#endif

	// should be tested
	#define EXT_NET_POLL_AVAILIABLE 0

#elif BOOST_OS_UNIX

	struct in_addr;
	struct in6_addr;
	struct sockaddr;
	struct sockaddr_in;
	struct sockaddr_in6;
	struct sockaddr_storage;
	
	struct addrinfo;
	struct addrinfoW;
	
	struct timeval;

	typedef int              socket_handle_type;
	typedef unsigned int     socklen_t;
	typedef socklen_t        sockoptlen_t;

	#if _POSIX_C_SOURCE >= 200112L
	#define EXT_NET_POLL_AVAILIABLE 1
	#else
	#define EXT_NET_POLL_AVAILIABLE 0
	#endif

#endif

#ifndef EXT_NET_USE_POLL
#define EXT_NET_USE_POLL EXT_NET_POLL_AVAILIABLE
#endif // EXT_NET_USE_POLL

#ifdef EXT_ENABLE_OPENSSL
/// forward some openssl types
struct ssl_st;
struct ssl_ctx_st;
struct ssl_method_st;

typedef struct ssl_st        SSL;
typedef struct ssl_ctx_st    SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
#endif // EXT_ENABLE_OPENSSL
