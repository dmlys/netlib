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
/// * addrinfo
/// * sockaddr
/// * socklen_t
/// * sockoptlen_t - type that setsockopt accepts as len parameter,
///                  normally it should same as socklen_t but on some platforms can be different
/// 

#if   BOOST_OS_WINDOWS

    struct addrinfo;
    struct addrinfoW;
    struct sockaddr;
	struct timeval;

    typedef std::uintptr_t   socket_handle_type;
    typedef int              socklen_t;
    typedef socklen_t        sockoptlen_t;

#elif BOOST_OS_LINUX

	struct addrinfo;
	struct sockaddr;
	struct timeval;

	typedef int              socket_handle_type;
	typedef unsigned int     socklen_t;
	typedef socklen_t        sockoptlen_t;

#elif BOOST_OS_CYGWIN

	struct addrinfo;
	struct sockaddr;
	struct timeval;

	typedef int              socket_handle_type;
	typedef int              socklen_t;
	typedef socklen_t        sockoptlen_t;
	
#elif BOOST_OS_HPUX

	// hp-ux have 2 net libraries, standard libc and libxnet
	struct addrinfo;
	struct sockaddr;
	struct timeval;

	typedef int              socket_handle_type;
	typedef std::size_t      socklen_t;

	// if defined _XOPEN_SOURCE - it's libxnet, you probably also should link with -lxnet
	#if defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE >= 500 || defined(_XOPEN_SOURCE_EXTENDED))
	    typedef socklen_t    sockoptlen_t;
	#else
	    typedef int          sockoptlen_t;
	#endif

#else

    struct addrinfo;
	struct sockaddr;
	struct timeval;

	typedef int              socket_handle_type;
	typedef unsigned int     socklen_t;
	typedef socklen_t        sockoptlen_t;

#endif


#ifdef EXT_ENABLE_OPENSSL
/// forward some openssl types
struct ssl_st;
struct ssl_ctx_st;
struct ssl_method_st;

typedef struct ssl_st        SSL;
typedef struct ssl_ctx_st    SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;
#endif // EXT_ENABLE_OPENSSL
