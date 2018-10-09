﻿#ifdef EXT_ENABLE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/dh.h>

#include <ext/netlib/openssl.hpp>
#include <boost/predef.h> // for BOOST_OS_WINDOWS
#include <boost/static_assert.hpp>

#if BOOST_OS_WINDOWS
#include <windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "crypt32.lib")
#endif // _MSC_VER

#endif // BOOST_OS_WINDOWS

namespace ext::netlib::openssl
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

	std::error_code openssl_geterror(int sslcode) noexcept
	{
		if (sslcode == SSL_ERROR_SSL || sslcode == SSL_ERROR_SYSCALL)
		{
			int err = ERR_get_error();
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

	std::error_code last_error() noexcept
	{
		int err = ::ERR_get_error();
		return std::error_code(err, openssl_err_category());
	}

	[[noreturn]] void throw_last_error(const std::string & errmsg)
	{
		throw std::system_error(last_error(), errmsg);
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
		::sk_X509_free(ca);
	}

	void rsa_deleter::operator()(RSA * rsa) const noexcept
	{
		::RSA_free(rsa);
	}

	void evp_pkey_deleter::operator()(EVP_PKEY * pkey) const noexcept
	{
		::EVP_PKEY_free(pkey);
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

	x509_uptr load_certificate(const char * data, std::size_t len, std::string_view passwd)
	{
		bio_uptr bio_uptr;

		auto * bio = ::BIO_new_mem_buf(data, static_cast<int>(len));
		bio_uptr.reset(bio);
		if (not bio) throw_last_error("ext::netlib::openssl::load_certificate: ::BIO_new_mem_buf failed");

		X509 * cert = ::PEM_read_bio_X509(bio, nullptr, password_callback, &passwd);
		if (not cert) throw_last_error("ext::netlib::openssl::load_certificate: ::PEM_read_bio_X509 failed");
		return x509_uptr(cert);
	}

	evp_pkey_uptr load_private_key(const char * data, std::size_t len, std::string_view passwd)
	{
		bio_uptr bio_uptr;

		auto * bio = BIO_new_mem_buf(data, static_cast<int>(len));
		bio_uptr.reset(bio);
		if (not bio) throw_last_error("ext::netlib::openssl::load_private_key: ::BIO_new_mem_buf failed");

		EVP_PKEY * pkey = ::PEM_read_bio_PrivateKey(bio, nullptr, password_callback, &passwd);
		if (not bio) throw_last_error("ext::netlib::openssl::load_private_key: ::PEM_read_bio_PrivateKey failed");
		return evp_pkey_uptr(pkey);
	}

	x509_uptr load_certificate_from_file(const char * path, std::string_view passwd)
	{
		std::FILE * fp = std::fopen(path, "r");
		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::netlib::openssl::load_certificate_from_file: std::fopen failed");
		}

		X509 * cert = ::PEM_read_X509(fp, nullptr, password_callback, &passwd);
		std::fclose(fp);

		if (not cert) throw_last_error("ext::netlib::openssl::load_certificate_from_file: ::PEM_read_X509 failed");
		return x509_uptr(cert);
	}

	evp_pkey_uptr load_private_key_from_file(const char * path, std::string_view passwd)
	{
		std::FILE * fp = std::fopen(path, "r");
		if (fp == nullptr)
		{
			std::error_code errc(errno, std::generic_category());
			throw std::system_error(errc, "ext::netlib::openssl::load_private_key_from_file: std::fopen failed");
		}

		EVP_PKEY * pkey = ::PEM_read_PrivateKey(fp, nullptr, password_callback, &passwd);
		std::fclose(fp);

		if (not pkey) throw_last_error("ext::netlib::openssl::load_private_key_from_file: ::PEM_read_PrivateKey failed");
		return evp_pkey_uptr(pkey);
	}

	ssl_ctx_uptr create_sslctx(X509 * cert, EVP_PKEY * pkey)
	{
		auto * method = ::SSLv23_server_method();
		return create_sslctx(method, cert, pkey);
	}

	ssl_ctx_uptr create_sslctx(const SSL_METHOD * method, X509 * cert, EVP_PKEY * pkey)
	{
		auto * ctx = ::SSL_CTX_new(method);

		ssl_ctx_uptr ssl_ctx_uptr(ctx);

		if (cert != nullptr)
		{
			if (::SSL_CTX_use_certificate(ctx, cert) !=1)
				throw_last_error("ext::netlib::openssl::create_sslctx: ::SSL_CTX_use_certificate failed");
		}

		if (pkey != nullptr)
		{
			if (::SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
				throw_last_error("ext::netlib::openssl::create_sslctx: ::SSL_CTX_use_PrivateKey failed");
		}

		return ssl_ctx_uptr;
	}

	ssl_ctx_uptr create_anonymous_sslctx()
	{
		auto * method = ::SSLv23_server_method();
		return create_anonymous_sslctx(method);
	}

	ssl_ctx_uptr create_anonymous_sslctx(const SSL_METHOD * method)
	{
		auto * ctx = ::SSL_CTX_new(method);

		ssl_ctx_uptr ssl_ctx_uptr(ctx);
		if (::SSL_CTX_set_cipher_list(ctx, "aNULL:eNULL") != 1)
			throw_last_error("ext::netlib::openssl::create_anonymous_sslctx: ::SSL_CTX_set_cipher_list failed");

		::DH * dh = ::DH_get_2048_256();
		::SSL_CTX_set_tmp_dh(ctx, dh);
		::DH_free(dh);

		return ssl_ctx_uptr;
	}
}

#endif // #ifdef EXT_ENABLE_OPENSSL