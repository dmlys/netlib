#ifdef EXT_ENABLE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/pkcs12.h>
#include <openssl/cms.h>

#include <codecvt>
#include <ext/codecvt_conv.hpp>

#include <boost/predef.h> // for BOOST_OS_WINDOWS
#include <boost/static_assert.hpp>

#include <ext/net/openssl.hpp>

#if BOOST_OS_WINDOWS
#include <windows.h>
#include <winsock2.h>

#ifdef _MSC_VER
#pragma comment(lib, "crypt32.lib")
#endif // _MSC_VER

#endif // BOOST_OS_WINDOWS


int  intrusive_ptr_add_ref(BIO * ptr)  { return ::BIO_up_ref(ptr); }
void intrusive_ptr_release(BIO * ptr)  { return ::BIO_vfree(ptr);   }

int  intrusive_ptr_add_ref(X509 * ptr) { return ::X509_up_ref(ptr); }
void intrusive_ptr_release(X509 * ptr) { return ::X509_free(ptr);   }

int  intrusive_ptr_add_ref(RSA * ptr)  { return ::RSA_up_ref(ptr);  }
void intrusive_ptr_release(RSA * ptr)  { return ::RSA_free(ptr);    }

int  intrusive_ptr_add_ref(EVP_PKEY * ptr) { return ::EVP_PKEY_up_ref(ptr); }
void intrusive_ptr_release(EVP_PKEY * ptr) { return ::EVP_PKEY_free(ptr);   }

int  intrusive_ptr_add_ref(SSL * ptr) { return ::SSL_up_ref(ptr); }
void intrusive_ptr_release(SSL * ptr) { return ::SSL_free(ptr);   }

int  intrusive_ptr_add_ref(SSL_CTX * ptr) { return ::SSL_CTX_up_ref(ptr); }
void intrusive_ptr_release(SSL_CTX * ptr) { return ::SSL_CTX_free(ptr);   }



namespace ext::net::openssl
{
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::none)              == SSL_ERROR_NONE);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::ssl)               == SSL_ERROR_SSL);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::want_read)         == SSL_ERROR_WANT_READ);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::want_write)        == SSL_ERROR_WANT_WRITE);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::want_X509_lookup)  == SSL_ERROR_WANT_X509_LOOKUP);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::syscall)           == SSL_ERROR_SYSCALL);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::zero_return)       == SSL_ERROR_ZERO_RETURN);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::want_connect)      == SSL_ERROR_WANT_CONNECT);
	BOOST_STATIC_ASSERT(static_cast<int>(ssl_error::want_accept)       == SSL_ERROR_WANT_ACCEPT);


	/************************************************************************/
	/*                      error_category                                  */
	/************************************************************************/
	struct openssl_err_category_impl : std::error_category
	{
		const char * name() const noexcept override;
		std::string message(int code) const override;
	};

	const char * openssl_err_category_impl::name() const noexcept
	{
		return "openssl_err";
	}

	std::string openssl_err_category_impl::message(int code) const
	{
		// https://www.openssl.org/docs/manmaster/crypto/ERR_error_string.html
		// openssl says that buffer should be at least 120 bytes long for ERR_error_string.
		const std::size_t buflen = 256;
		char errbuf[buflen];
		::ERR_error_string_n(code, errbuf, buflen);
		// errbuf will be null terminated
		return errbuf;
	}

	struct openssl_ssl_category_impl : std::error_category
	{
		const char * name() const noexcept override;
		std::string message(int code) const override;
	};

	const char * openssl_ssl_category_impl::name() const noexcept
	{
		return "openssl_ssl";
	}

	std::string openssl_ssl_category_impl::message(int code) const
	{
		switch (code)
		{
			case SSL_ERROR_NONE:             return "SSL_ERROR_NONE";
			case SSL_ERROR_SSL:              return "SSL_ERROR_SSL";
			case SSL_ERROR_WANT_READ:        return "SSL_ERROR_WANT_READ";
			case SSL_ERROR_WANT_WRITE:       return "SSL_ERROR_WANT_WRITE";
			case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
			case SSL_ERROR_SYSCALL:          return "SSL_ERROR_SYSCALL";
			
			case SSL_ERROR_ZERO_RETURN:      return "SSL_ERROR_ZERO_RETURN";
			case SSL_ERROR_WANT_CONNECT:     return "SSL_ERROR_WANT_CONNECT";
			case SSL_ERROR_WANT_ACCEPT:      return "SSL_ERROR_WANT_ACCEPT";
			
			default: return "SSL_ERROR_UNKNOWN";
		}
	}
	
	openssl_err_category_impl openssl_err_category_instance;
	openssl_ssl_category_impl openssl_ssl_category_instance;

	const std::error_category & openssl_err_category() noexcept
	{
		return openssl_err_category_instance;
	}

	const std::error_category & openssl_ssl_category() noexcept
	{
		return openssl_ssl_category_instance;
	}

	std::error_code openssl_geterror(int sslcode, error_retrieve rtype) noexcept
	{
		if (sslcode == SSL_ERROR_SSL || sslcode == SSL_ERROR_SYSCALL)
		{
			int err = rtype == error_retrieve::get ? ::ERR_get_error() : ::ERR_peek_error();
			if (err) return {err, openssl_err_category()};
			
#if BOOST_OS_WINDOWS
			err = ::WSAGetLastError();
#else
			err = errno;
#endif
			if (err) return {err, std::system_category()};
		}
		
		return {sslcode, openssl_ssl_category()};
	}

	void openssl_clear_errors() noexcept
	{
		::ERR_clear_error();
	}

	std::error_code last_error(error_retrieve rtype) noexcept
	{
		int err = rtype == error_retrieve::get ? ::ERR_get_error() : ::ERR_peek_error();
		return std::error_code(err, openssl_err_category());
	}

	[[noreturn]] void throw_last_error(const std::string & errmsg, error_retrieve rtype)
	{
		throw std::system_error(last_error(rtype), errmsg);
	}

	static int print_error_queue_string_cb(const char * data, std::size_t len, void * ptr)
	{
		auto * pstr = static_cast<std::string *>(ptr);
		pstr->append(data, len);
		return 1;
	}

	static int print_error_queue_streambuf_cb(const char * data, std::size_t len, void * ptr)
	{
		auto * pos = static_cast<std::streambuf *>(ptr);
		return pos->sputn(data, len) == static_cast<std::streamsize>(len);
	}

	static int print_error_queue_ostream_cb(const char * data, std::size_t len, void * ptr)
	{
		auto * pos = static_cast<std::ostream *>(ptr);
		pos->write(data, len);
		return static_cast<bool>(*pos);
	}

	void print_error_queue(std::string & str)
	{
		::ERR_print_errors_cb(print_error_queue_string_cb, &str);
	}

	void print_error_queue(std::ostream & os)
	{
		::ERR_print_errors_cb(print_error_queue_ostream_cb, &os);
	}

	void print_error_queue(std::streambuf & os)
	{
		::ERR_print_errors_cb(print_error_queue_streambuf_cb, &os);
	}

	std::string print_error_queue()
	{
		std::string str;
		print_error_queue(str);
		return str;
	}

	/************************************************************************/
	/*                  init/cleanup                                        */
	/************************************************************************/
	void openssl_init()
	{
		SSL_load_error_strings();
		SSL_library_init();
	}

	void openssl_cleanup()
	{
		// https://mta.openssl.org/pipermail/openssl-users/2015-January/000326.html
		CRYPTO_cleanup_all_ex_data();
		ERR_free_strings();
		EVP_cleanup();
	}

	/************************************************************************/
	/*                  smart ptr stuff                                     */
	/************************************************************************/
	void ssl_deleter::operator()(SSL * ssl) const noexcept
	{
		::SSL_free(ssl);
	}

	void ssl_ctx_deleter::operator()(SSL_CTX * sslctx) const noexcept
	{
		::SSL_CTX_free(sslctx);
	}

	void bio_deleter::operator()(BIO * bio) const noexcept
	{
		::BIO_vfree(bio);
	}

	void x509_deleter::operator()(X509 * cert) const noexcept
	{
		::X509_free(cert);
	}

	void stackof_x509_deleter::operator()(STACK_OF(X509) * ca) const noexcept
	{
		// https://wiki.nikhef.nl/grid/How_to_handle_OpenSSL_and_not_get_hurt_and_what_does_that_library_call_really_do%3F#Proper_memory_liberation_of_a_STACK_OF_.28X509.29_.2A
		// sk_X509_pop_free should be used instead of sk_X509_free, or memory leaks will occur or certificate chains longer than 1
		::sk_X509_pop_free(ca, ::X509_free);
	}

	void rsa_deleter::operator()(RSA * rsa) const noexcept
	{
		::RSA_free(rsa);
	}

	void evp_pkey_deleter::operator()(EVP_PKEY * pkey) const noexcept
	{
		::EVP_PKEY_free(pkey);
	}

	void pkcs12_deleter::operator()(PKCS12 * pkcs12) const noexcept
	{
		::PKCS12_free(pkcs12);
	}

	/************************************************************************/
	/*                  utility stuff                                       */
	/************************************************************************/
	static int password_callback(char * buff, int bufsize, int rwflag, void * userdata)
	{
		auto & passwd = *static_cast<std::string_view *>(userdata);
		passwd.copy(buff, bufsize);
		return 0;
	}

	x509_iptr load_certificate(const char * data, std::size_t len, std::string_view passwd)
	{
		bio_uptr bio_uptr;

		auto * bio = ::BIO_new_mem_buf(data, static_cast<int>(len));
		bio_uptr.reset(bio);
		if (not bio) throw_last_error("ext::net::openssl::load_certificate: ::BIO_new_mem_buf failed");

		X509 * cert = ::PEM_read_bio_X509(bio, nullptr, password_callback, &passwd);
		if (not cert) throw_last_error("ext::net::openssl::load_certificate: ::PEM_read_bio_X509 failed");
		return x509_iptr(cert, ext::noaddref);
	}

	evp_pkey_iptr load_private_key(const char * data, std::size_t len, std::string_view passwd)
	{
		bio_uptr bio_uptr;

		auto * bio = BIO_new_mem_buf(data, static_cast<int>(len));
		bio_uptr.reset(bio);
		if (not bio) throw_last_error("ext::net::openssl::load_private_key: ::BIO_new_mem_buf failed");

		EVP_PKEY * pkey = ::PEM_read_bio_PrivateKey(bio, nullptr, password_callback, &passwd);
		if (not bio) throw_last_error("ext::net::openssl::load_private_key: ::PEM_read_bio_PrivateKey failed");
		return evp_pkey_iptr(pkey, ext::noaddref);
	}

	x509_iptr load_certificate_from_file(const char * path, std::string_view passwd)
	{
#if BOOST_OS_WINDOWS
		std::codecvt_utf8<wchar_t> cvt;
		auto wpath = ext::codecvt_convert::from_bytes(cvt, ext::str_view(path));
		std::FILE * fp = ::_wfopen(wpath.c_str(), L"r");
#else
		std::FILE * fp = std::fopen(path, "r");
#endif
		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::net::openssl::load_certificate_from_file: std::fopen failed");
		}

		X509 * cert = ::PEM_read_X509(fp, nullptr, password_callback, &passwd);
		std::fclose(fp);

		if (not cert) throw_last_error("ext::net::openssl::load_certificate_from_file: ::PEM_read_X509 failed");
		return x509_iptr(cert, ext::noaddref);
	}

	x509_iptr load_certificate_from_file(const wchar_t * wpath, std::string_view passwd)
	{
#if not BOOST_OS_WINDOWS
		std::codecvt_utf8<wchar_t> cvt;
		auto path = ext::codecvt_convert::to_bytes(cvt, ext::str_view(wpath));
		std::FILE * fp = std::fopen(path.c_str(), "r");
#else
		std::FILE * fp = ::_wfopen(wpath, L"r");
#endif
		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::net::openssl::load_certificate_from_file: std::fopen failed");
		}

		X509 * cert = ::PEM_read_X509(fp, nullptr, password_callback, &passwd);
		std::fclose(fp);

		if (not cert) throw_last_error("ext::net::openssl::load_certificate_from_file: ::PEM_read_X509 failed");
		return x509_iptr(cert, ext::noaddref);
	}

	x509_iptr load_certificate_from_file(std::FILE * file, std::string_view passwd)
	{
		assert(file);
		X509 * cert = ::PEM_read_X509(file, nullptr, password_callback, &passwd);

		if (not cert) throw_last_error("ext::net::openssl::load_certificate_from_file: ::PEM_read_X509 failed");
		return x509_iptr(cert, ext::noaddref);
	}


	evp_pkey_iptr load_private_key_from_file(const char * path, std::string_view passwd)
	{
#if BOOST_OS_WINDOWS
		std::codecvt_utf8<wchar_t> cvt;
		auto wpath = ext::codecvt_convert::from_bytes(cvt, ext::str_view(path));
		std::FILE * fp = ::_wfopen(wpath.c_str(), L"r");
#else
		std::FILE * fp = std::fopen(path, "r");
#endif

		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::net::openssl::load_private_key_from_file: std::fopen failed");
		}

		//                  traditional or PKCS#8 format
		EVP_PKEY * pkey = ::PEM_read_PrivateKey(fp, nullptr, password_callback, &passwd);
		std::fclose(fp);

		if (not pkey) throw_last_error("ext::net::openssl::load_private_key_from_file: ::PEM_read_PrivateKey failed");
		return evp_pkey_iptr(pkey, ext::noaddref);
	}

	evp_pkey_iptr load_private_key_from_file(const wchar_t * wpath, std::string_view passwd)
	{
#if not BOOST_OS_WINDOWS
		std::codecvt_utf8<wchar_t> cvt;
		auto path = ext::codecvt_convert::to_bytes(cvt, ext::str_view(wpath));
		std::FILE * fp = std::fopen(path.c_str(), "r");
#else
		std::FILE * fp = ::_wfopen(wpath, L"r");
#endif

		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::net::openssl::load_private_key_from_file: std::fopen failed");
		}

		//                  traditional or PKCS#8 format
		EVP_PKEY * pkey = ::PEM_read_PrivateKey(fp, nullptr, password_callback, &passwd);
		std::fclose(fp);

		if (not pkey) throw_last_error("ext::net::openssl::load_private_key_from_file: ::PEM_read_PrivateKey failed");
		return evp_pkey_iptr(pkey, ext::noaddref);
	}

	evp_pkey_iptr load_private_key_from_file(std::FILE * file, std::string_view passwd)
	{
		assert(file);
		//                  traditional or PKCS#8 format
		EVP_PKEY * pkey = ::PEM_read_PrivateKey(file, nullptr, password_callback, &passwd);

		if (not pkey) throw_last_error("ext::net::openssl::load_private_key_from_file: ::PEM_read_PrivateKey failed");
		return evp_pkey_iptr(pkey, ext::noaddref);
	}

	pkcs12_uptr load_pkcs12(const char * data, std::size_t len)
	{
		bio_uptr source_bio(::BIO_new_mem_buf(data, static_cast<int>(len)));
		if (not source_bio) throw_last_error("ext::net::openssl::load_pkcs12: ::BIO_new_mem_buf failed");

		pkcs12_uptr pkcs12(::d2i_PKCS12_bio(source_bio.get(), nullptr));
		if (not pkcs12) throw_last_error("ext::net::openssl::load_pkcs12_from_file: ::d2i_PKCS12_fp failed");
		return pkcs12;
	}

	pkcs12_uptr load_pkcs12_from_file(const char * path)
	{
#if BOOST_OS_WINDOWS
		std::codecvt_utf8<wchar_t> cvt;
		auto wpath = ext::codecvt_convert::from_bytes(cvt, ext::str_view(path));
		std::FILE * fp = ::_wfopen(wpath.c_str(), L"r");
#else
		std::FILE * fp = std::fopen(path, "r");
#endif

		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::net::openssl::load_pkcs12_from_file: std::fopen failed");
		}

		pkcs12_uptr pkcs12(::d2i_PKCS12_fp(fp, nullptr));
		std::fclose(fp);

		if (not pkcs12) throw_last_error("ext::net::openssl::load_pkcs12_from_file: ::d2i_PKCS12_fp failed");
		return pkcs12;
	}

	pkcs12_uptr load_pkcs12_from_file(const wchar_t * wpath)
	{
#if not BOOST_OS_WINDOWS
		std::codecvt_utf8<wchar_t> cvt;
		auto path = ext::codecvt_convert::to_bytes(cvt, ext::str_view(wpath));
		std::FILE * fp = std::fopen(path.c_str(), "r");
#else
		std::FILE * fp = ::_wfopen(wpath, L"r");
#endif

		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::net::openssl::load_pkcs12_from_file: std::fopen failed");
		}

		pkcs12_uptr pkcs12(::d2i_PKCS12_fp(fp, nullptr));
		std::fclose(fp);

		if (not pkcs12) throw_last_error("ext::net::openssl::load_pkcs12_from_file: ::d2i_PKCS12_fp failed");
		return pkcs12;
	}

	pkcs12_uptr load_pkcs12_from_file(std::FILE * file)
	{
		assert(file);
		pkcs12_uptr pkcs12(::d2i_PKCS12_fp(file, nullptr));

		if (not pkcs12) throw_last_error("ext::net::openssl::load_pkcs12_from_file: ::d2i_PKCS12_fp failed");
		return pkcs12;
	}

	void parse_pkcs12(PKCS12 * pkcs12, std::string passwd, evp_pkey_iptr & evp_pkey, x509_iptr & x509, stackof_x509_uptr & ca)
	{
		X509 * raw_cert = nullptr;
		EVP_PKEY * raw_pkey = nullptr;
		STACK_OF(X509) * raw_ca = nullptr;

		int res = ::PKCS12_parse(pkcs12, passwd.c_str(), &raw_pkey, &raw_cert, &raw_ca);
		if (res <= 0) throw_last_error("ext::net::openssl::parse_pkcs12: ::PKCS12_parse failed");

		evp_pkey.reset(raw_pkey, ext::noaddref);
		x509.reset(raw_cert, ext::noaddref);
		ca.reset(raw_ca);
	}

	auto parse_pkcs12(PKCS12 * pkcs12, std::string passwd) -> std::tuple<evp_pkey_iptr, x509_iptr, stackof_x509_uptr>
	{
		std::tuple<evp_pkey_iptr, x509_iptr, stackof_x509_uptr> result;
		parse_pkcs12(pkcs12, passwd, std::get<0>(result), std::get<1>(result), std::get<2>(result));
		return result;
	}


	ssl_ctx_iptr create_sslctx(X509 * cert, EVP_PKEY * pkey, stack_st_X509 * ca_chain)
	{
		auto * method = ::SSLv23_server_method();
		return create_sslctx(method, cert, pkey, ca_chain);
	}

	ssl_ctx_iptr create_sslctx(const SSL_METHOD * method, X509 * cert, EVP_PKEY * pkey, stack_st_X509 * ca_chain)
	{
		auto * ctx = ::SSL_CTX_new(method);

		ssl_ctx_iptr ssl_ctx_iptr(ctx, ext::noaddref);

		if (::SSL_CTX_use_cert_and_key(ctx, cert, pkey, ca_chain, 1) != 1)
			throw_last_error("ext::net::openssl::create_sslctx: ::SSL_CTX_use_cert_and_key failed");

		return ssl_ctx_iptr;
	}

	ssl_ctx_iptr create_anonymous_sslctx()
	{
		auto * method = ::SSLv23_server_method();
		return create_anonymous_sslctx(method);
	}

	ssl_ctx_iptr create_anonymous_sslctx(const SSL_METHOD * method)
	{
		auto * ctx = ::SSL_CTX_new(method);

		ssl_ctx_iptr ssl_ctx_iptr(ctx, ext::noaddref);
		if (::SSL_CTX_set_cipher_list(ctx, "aNULL:eNULL") != 1)
			throw_last_error("ext::net::openssl::create_anonymous_sslctx: ::SSL_CTX_set_cipher_list failed");

		::DH * dh = ::DH_get_2048_256();
		::SSL_CTX_set_tmp_dh(ctx, dh);
		::DH_free(dh);

		return ssl_ctx_iptr;
	}

	struct cms_contentinfo_deleter { void operator()(CMS_ContentInfo * info) { CMS_ContentInfo_free(info); } };
	using cms_contentinfo_ptr = std::unique_ptr<CMS_ContentInfo, cms_contentinfo_deleter>;

	std::string sign_mail(EVP_PKEY * pkey, X509 * x509, stack_st_X509 * additional_certs, std::string_view msg_body, bool detached)
	{
		bio_uptr bio_input_ptr, bio_output_ptr;
		bio_input_ptr.reset( ::BIO_new_mem_buf(msg_body.data(), static_cast<int>(msg_body.size())) );
		bio_output_ptr.reset( ::BIO_new(::BIO_s_mem()) );

		if (not bio_input_ptr)  throw_last_error("ext::net::openssl::sign_mail: input  BIO_mem fail(::BIO_new_mem_buf)");
		if (not bio_output_ptr) throw_last_error("ext::net::openssl::sign_mail: output BIO_mem fail(::BIO_new(::BIO_s_mem()))");

		int flags = CMS_STREAM | CMS_CRLFEOL;
		if (detached) flags |= CMS_DETACHED;

		cms_contentinfo_ptr cms_info(::CMS_sign(x509, pkey, additional_certs, bio_input_ptr.get(), flags));
		if (not cms_info) throw_last_error("ext::net::openssl::sign_mail: CMS_sign call failure");

		int res = ::SMIME_write_CMS(bio_output_ptr.get(), cms_info.get(), bio_input_ptr.get(), flags);
		if (res <= 0) throw_last_error("ext::net::openssl::sign_mail: SMIME_write_CMS call failure");

		char * data;
		int len = BIO_get_mem_data(bio_output_ptr.get(), &data);
		return std::string(data, len);
	}
}

#endif // #ifdef EXT_ENABLE_OPENSSL
