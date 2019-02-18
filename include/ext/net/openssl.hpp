#pragma once
#ifdef EXT_ENABLE_OPENSSL
#include <memory>
#include <string>
#include <string_view>
#include <system_error>

/// forward some openssl types
struct bio_st;
struct x509_st;
struct rsa_st;
struct evp_pkey_st;

typedef bio_st           BIO;
typedef x509_st          X509;
typedef rsa_st           RSA;
typedef evp_pkey_st      EVP_PKEY;

struct stack_st_X509;

struct ssl_st;
struct ssl_ctx_st;
struct ssl_method_st;

typedef struct ssl_st        SSL;
typedef struct ssl_ctx_st    SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;


/// Simple openssl utilities, mostly for socket_stream implementations of ssl functionality.
/// error category, startup/clean up routines, may be something other
namespace ext::net::openssl
{
	// those can be used as err == ext::net::openssl_error::zero_return.
	// also we do not include openssl/ssl.h, those definition are asserted in ext/openssl.cpp
	enum class ssl_error
	{
		none             = 0, // SSL_ERROR_NONE
		ssl              = 1, // SSL_ERROR_SSL
		want_read        = 2, // SSL_ERROR_WANT_READ
		want_write       = 3, // SSL_ERROR_WANT_WRITE
		want_X509_lookup = 4, // SSL_ERROR_WANT_X509_LOOKUP
		syscall          = 5, // SSL_ERROR_SYSCALL
		zero_return      = 6, // SSL_ERROR_ZERO_RETURN
		want_connect     = 7, // SSL_ERROR_WANT_CONNECT
		want_accept      = 8, // SSL_ERROR_WANT_ACCEPT
	};

	/// error category for openssl errors from ERR_*
	const std::error_category & openssl_err_category() noexcept;
	/// error category for openssl errors from SSL_*
	const std::error_category & openssl_ssl_category() noexcept;

	/// интеграция с system_error
	inline std::error_code make_error_code(ssl_error val) noexcept           { return {static_cast<int>(val), openssl_ssl_category()}; }
	inline std::error_condition make_error_condition(ssl_error val) noexcept { return {static_cast<int>(val), openssl_ssl_category()}; }

	/// создает error_code по заданному sslcode полученному с помощью SSL_get_error(..., ret)
	/// если sslcode == SSL_ERROR_SYSCALL, проверяет ERR_get_error() / system error,
	/// если валидны - выставляет их и openssl_err_category,
	/// иначе выставляет openssl_ssl_category
	std::error_code openssl_geterror(int sslcode) noexcept;

	/// returns last SSL error via ::ERR_get_error()
	std::error_code last_error() noexcept;
	/// throws std::system_error with last_error error_code
	[[noreturn]] void throw_last_error(const std::string & errmsg);

	/// per process initialization
	void openssl_init();
	/// per process cleanup
	void openssl_cleanup();


	// some smart pointers helpers
	struct ssl_deleter      { void operator()(SSL * ssl)        const noexcept; };
	struct ssl_ctx_deleter  { void operator()(SSL_CTX * sslctx) const noexcept; };

	struct bio_deleter      { void operator()(BIO * bio)       const noexcept; };
	struct x509_deleter     { void operator()(X509 * cert)     const noexcept; };
	struct rsa_deleter      { void operator()(RSA * rsa)       const noexcept; };
	struct evp_pkey_deleter { void operator()(EVP_PKEY * pkey) const noexcept; };

	struct stackof_x509_deleter { void operator()(stack_st_X509 * ca) const noexcept; };

	using ssl_uptr     = std::unique_ptr<SSL, ssl_deleter>;
	using ssl_ctx_uptr = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;

	using bio_uptr      = std::unique_ptr<BIO, bio_deleter>;
	using x509_uptr     = std::unique_ptr<X509, x509_deleter>;
	using rsa_uptr      = std::unique_ptr<RSA, rsa_deleter>;
	using evp_pkey_uptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;

	using stackof_x509_uptr = std::unique_ptr<stack_st_X509, stackof_x509_deleter>;


	/// Loads X509 certificate from given memory location and with optional password(password probably will never be used.
	/// Throws std::system_error in case of errors
	x509_uptr     load_certificate(const char * data, std::size_t len, std::string_view passwd = "");
	// loads private key from given memory location and with optional password
	/// Throws std::system_error in case of errors
	evp_pkey_uptr load_private_key(const char * data, std::size_t len, std::string_view passwd = "");

	inline x509_uptr     load_certificate(std::string_view str, std::string_view passwd = "") { return load_certificate(str.data(), str.size(), passwd); }
	inline evp_pkey_uptr load_private_key(std::string_view str, std::string_view passwd = "") { return load_private_key(str.data(), str.size(), passwd); }

	/// Loads X509 certificate from given path and with optional password
	/// Throws std::system_error in case of errors
	x509_uptr load_certificate_from_file(const char * path, std::string_view passwd = "");
	// loads private key from given given path and with optional password
	/// Throws std::system_error in case of errors
	evp_pkey_uptr load_private_key_from_file(const char * path, std::string_view passwd);

	/// creates SSL_CTX with given SSL method and sets given certificate and private key
	ssl_ctx_uptr create_sslctx(const SSL_METHOD * method, X509 * cert, EVP_PKEY * pkey);
	/// creates SSL_CTX with SSLv23_server_method and sets given certificate and private key
	ssl_ctx_uptr create_sslctx(X509 * cert, EVP_PKEY * pkey);

	/// creates SSL_CTX with given SSL method; sets cipher LIST to "aNULL,eNULL"
	/// which is alias for "The cipher suites offering no authentication."
	/// see https://www.openssl.org/docs/man1.1.0/apps/ciphers.html,
	/// also invokes SSL_CTX_set_tmp_dh with result of DH_get_2048_256.
	///
	/// NOTE: this is insecure and should not be used at all,
	///       but allows establishing connection without certificates.
	///       most clients have those ciphers disabled by default
	ssl_ctx_uptr create_anonymous_sslctx(const SSL_METHOD * method);
	///	same as above with SSLv23_server_method
	ssl_ctx_uptr create_anonymous_sslctx();
}

namespace ext::net
{
	// because those have openssl in theirs names - bring them to ext namespace
	using openssl::openssl_err_category;
	using openssl::openssl_ssl_category;
	using openssl::openssl_geterror;

	using openssl::openssl_init;
	using openssl::openssl_cleanup;
	
	typedef openssl::ssl_error  openssl_error;
}

namespace std
{
	template <>
	struct is_error_code_enum<ext::net::openssl::ssl_error>
		: std::true_type { };
}

#endif // EXT_ENABLE_OPENSSL
