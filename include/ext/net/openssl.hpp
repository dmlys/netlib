#pragma once
#ifdef EXT_ENABLE_OPENSSL
#include <memory>
#include <tuple>
#include <ostream>
#include <string>
#include <string_view>
#include <system_error>
#include <ext/intrusive_ptr.hpp>

/// forward some openssl types
struct bio_st;
struct x509_st;
struct rsa_st;
struct evp_pkey_st;
struct PKCS12_st;

typedef bio_st           BIO;
typedef x509_st          X509;
typedef rsa_st           RSA;
typedef evp_pkey_st      EVP_PKEY;
typedef PKCS12_st        PKCS12;

struct stack_st_X509;

struct ssl_st;
struct ssl_ctx_st;
struct ssl_method_st;

typedef struct ssl_st        SSL;
typedef struct ssl_ctx_st    SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;


int  intrusive_ptr_add_ref(BIO * ptr);
void intrusive_ptr_release(BIO * ptr);

int  intrusive_ptr_add_ref(X509 * ptr);
void intrusive_ptr_release(X509 * ptr);

int  intrusive_ptr_add_ref(RSA * ptr);
void intrusive_ptr_release(RSA * ptr);

int  intrusive_ptr_add_ref(EVP_PKEY * ptr);
void intrusive_ptr_release(EVP_PKEY * ptr);

int  intrusive_ptr_add_ref(SSL * ptr);
void intrusive_ptr_release(SSL * ptr);

int  intrusive_ptr_add_ref(SSL_CTX * ptr);
void intrusive_ptr_release(SSL_CTX * ptr);


/// Simple openssl utilities, mostly for socket_stream implementations of ssl functionality.
/// error category, startup/clean up routines, may be something other
namespace ext::net::openssl
{
	/// OpenSSL stores it's errors into thread local queue.
	/// If something bad happens more than one error can be pushed into that queue.
	/// That sorta conflicts with last_error mechanism, which can only report one error.
	/// Even more: error can have some associated runtime data, source file name and line number, std::error_code does not supports that even more.
	/// print_error_queue(::ERR_print_errors) functions can print them just fine, whole queue with all data;
	/// so logging/printing errors can be more convenient with those.
	/// ERR_get_error, through, removes error from queue, and ::ERR_print_errors will miss that error
	///
	/// So some of this library functions and each ext::net::socket_streambuf object provide error_retrieve_type enum pointing how to take openssl error: get or peek
	/// By default it's always get, but if you more comfortable with print_error_queue - you can change to peek, and than use one, just don't forget to call openssl_clear_errors
	enum class error_retrieve : unsigned
	{
		get,  /// use ::ERR_get_error
		peek, /// use ::ERR_peek_error, don't forget to call openssl_clear_errors after examining errors
	};

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
	std::error_code openssl_geterror(int sslcode, error_retrieve rtype = error_retrieve::get) noexcept;

	/// cleans OpenSSL error queue, calls ERR_clear_error
	void openssl_clear_errors() noexcept;

	/// returns last SSL error via ::ERR_get_error()
	std::error_code last_error(error_retrieve rtype = error_retrieve::get) noexcept;
	/// throws std::system_error with last_error error_code
	[[noreturn]] void throw_last_error(const std::string & errmsg, error_retrieve rtype = error_retrieve::get);

	/// prints openssl error queue into string, see ::ERR_print_errors,
	/// error queue will be empty after executing this function
	void print_error_queue(std::string & str);
	/// prints openssl error queue into ostream, see ::ERR_print_errors,
	/// error queue will be empty after executing this function
	void print_error_queue(std::ostream & os);
	/// prints openssl error queue into streambuf, see ::ERR_print_errors,
	/// error queue will be empty after executing this function
	void print_error_queue(std::streambuf & os);
	/// prints openssl error queue into string and returns it, see ::ERR_print_errors,
	/// error queue will be empty after executing this function
	std::string print_error_queue();

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
	struct pkcs12_deleter   { void operator()(PKCS12 * pkcs12) const noexcept; };

	struct stackof_x509_deleter { void operator()(stack_st_X509 * ca) const noexcept; };

	using ssl_uptr     = std::unique_ptr<SSL, ssl_deleter>;
	using ssl_ctx_uptr = std::unique_ptr<SSL_CTX, ssl_ctx_deleter>;

	using bio_uptr      = std::unique_ptr<BIO, bio_deleter>;
	using x509_uptr     = std::unique_ptr<X509, x509_deleter>;
	using rsa_uptr      = std::unique_ptr<RSA, rsa_deleter>;
	using evp_pkey_uptr = std::unique_ptr<EVP_PKEY, evp_pkey_deleter>;
	using pkcs12_uptr   = std::unique_ptr<PKCS12, pkcs12_deleter>;

	using stackof_x509_uptr = std::unique_ptr<stack_st_X509, stackof_x509_deleter>;



	using ssl_iptr      = ext::intrusive_ptr<SSL>;
	using ssl_ctx_iptr  = ext::intrusive_ptr<SSL_CTX>;
	using x509_iptr     = ext::intrusive_ptr<X509>;

	using bio_iptr      = ext::intrusive_ptr<BIO>;
	using x509_iptr     = ext::intrusive_ptr<X509>;
	using rsa_iptr      = ext::intrusive_ptr<RSA>;
	using evp_pkey_iptr = ext::intrusive_ptr<EVP_PKEY>;


	/// Loads X509 certificate from given memory location and with optional password(password probably will never be used.
	/// Throws std::system_error in case of errors
	x509_iptr     load_certificate(const char * data, std::size_t len, std::string_view passwd = "");
	// loads private key from given memory location and with optional password
	/// Throws std::system_error in case of errors
	evp_pkey_iptr load_private_key(const char * data, std::size_t len, std::string_view passwd = "");

	inline x509_iptr     load_certificate(std::string_view str, std::string_view passwd = "") { return load_certificate(str.data(), str.size(), passwd); }
	inline evp_pkey_iptr load_private_key(std::string_view str, std::string_view passwd = "") { return load_private_key(str.data(), str.size(), passwd); }

	/// Loads X509 certificate from given path and with optional password
	/// Throws std::system_error in case of errors
	x509_iptr     load_certificate_from_file(const char * path, std::string_view passwd = "");
	x509_iptr     load_certificate_from_file(const wchar_t * path, std::string_view passwd = "");
	x509_iptr     load_certificate_from_file(std::FILE * file, std::string_view passwd = "");

	/// loads private key from given given path and with optional password
	/// Throws std::system_error in case of errors
	evp_pkey_iptr load_private_key_from_file(const char * path, std::string_view passwd = "");
	evp_pkey_iptr load_private_key_from_file(const wchar_t * path, std::string_view passwd = "");
	evp_pkey_iptr load_private_key_from_file(std::FILE * path, std::string_view passwd = "");

	/// Loads PKCS12 file from given memory location.
	/// Throws std::system_error in case of errors
	pkcs12_uptr load_pkcs12(const char * data, std::size_t len);
	/// Loads PKCS12 file from given path.
	/// Throws std::system_error in case of errors
	pkcs12_uptr load_pkcs12_from_file(const char * path);
	pkcs12_uptr load_pkcs12_from_file(const wchar_t * path);
	pkcs12_uptr load_pkcs12_from_file(std::FILE * file);

	inline pkcs12_uptr load_pkcs12(std::string_view str) { return load_pkcs12(str.data(), str.size()); }

	inline x509_iptr     load_certificate_from_file(const std::string & path, std::string_view passwd = "") { return load_certificate_from_file(path.c_str(), passwd); }
	inline evp_pkey_iptr load_private_key_from_file(const std::string & path, std::string_view passwd = "") { return load_private_key_from_file(path.c_str(), passwd); }
	inline pkcs12_uptr   load_pkcs12_from_file(const std::string & path) { return load_pkcs12_from_file(path.c_str()); }

	inline x509_iptr     load_certificate_from_file(const std::wstring & path, std::string_view passwd = "") { return load_certificate_from_file(path.c_str(), passwd); }
	inline evp_pkey_iptr load_private_key_from_file(const std::wstring & path, std::string_view passwd = "") { return load_private_key_from_file(path.c_str(), passwd); }
	inline pkcs12_uptr   load_pkcs12_from_file(const std::wstring & path) { return load_pkcs12_from_file(path.c_str()); }

	/// Parses PKCS12 into private key, x509 certificate and certificate authorities
	/// Throws std::system_error in case of errors
	void parse_pkcs12(PKCS12 * pkcs12, std::string passwd, evp_pkey_iptr & evp_pkey, x509_iptr & x509, stackof_x509_uptr & ca);
	auto parse_pkcs12(PKCS12 * pkcs12, std::string passwd = "") -> std::tuple<evp_pkey_iptr, x509_iptr, stackof_x509_uptr>;

	/// creates SSL_CTX with given SSL method and sets given certificate and private key and CA chain(SSL_CTX_use_cert_and_key)
	ssl_ctx_iptr create_sslctx(const SSL_METHOD * method, X509 * cert, EVP_PKEY * pkey, stack_st_X509 * ca_chain = nullptr);
	/// creates SSL_CTX with SSLv23_server_method and sets given certificate, private key and CA chain(SSL_CTX_use_cert_and_key)
	ssl_ctx_iptr create_sslctx(X509 * cert, EVP_PKEY * pkey, stack_st_X509 * ca_chain = nullptr);

	/// creates SSL_CTX with given SSL method; sets cipher LIST to "aNULL,eNULL"
	/// which is alias for "The cipher suites offering no authentication."
	/// see https://www.openssl.org/docs/man1.1.0/apps/ciphers.html,
	/// also invokes SSL_CTX_set_tmp_dh with result of DH_get_2048_256.
	///
	/// NOTE: this is insecure and should not be used at all,
	///       but allows establishing connection without certificates.
	///       most clients have those ciphers disabled by default
	ssl_ctx_iptr create_anonymous_sslctx(const SSL_METHOD * method);
	///	same as above with SSLv23_server_method
	ssl_ctx_iptr create_anonymous_sslctx();

	/// signs email(msg_body) with given private key, x509 certificate and ca's
	std::string sign_mail(EVP_PKEY * pkey, X509 * x509, stack_st_X509 * ca, std::string_view msg_body, bool detached);
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
