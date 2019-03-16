#pragma once
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include <ext/library_logger/logger.hpp>
#include <ext/net/mime/mail_encoding.hpp>
#include <ext/net/smtp/smtp_extensions.hpp>

#if EXT_ENABLE_OPENSSL
#include <ext/net/openssl.hpp>
#endif

namespace ext::net::mail::simple
{
	struct mail_attachment
	{
		// all strings are must be in utf-8
		
		std::string name;
		std::string content;
	};

	struct message
	{
		// all strings are must be in utf-8

		std::string from;
		std::string reply_to;

		std::vector<std::string> recipients;
		std::vector<std::string> cc_recipients;
		std::vector<std::string> bcc_recipients;

		std::string subject;
		std::string body;
		std::string content_type = "text/plain";
		mime::mail_encoding body_encoding = mime::mail_encoding::bit7; // encoding hint
		bool force_encoding = false;

		std::vector<mail_attachment> attachments;

#if EXT_ENABLE_OPENSSL
		// certificate and private key for signing
		openssl::evp_pkey_uptr private_key;
		openssl::x509_uptr     x509;
		openssl::stackof_x509_uptr ca;
		bool sign_detached = true;
#endif

	};

	struct send_params
	{
		// all strings are must be in utf-8

		std::string smtp_addr = "localhost";
		std::string smtp_service = "smtp";
		
#if EXT_ENABLE_OPENSSL
		bool smtp_startssl = false;
#endif

		std::string auth_user;
		std::string auth_password;
		bool auth_login = false;
	};

	void send_mail(const message & msg, const send_params & sp, ext::library_logger::logger * log = nullptr);
	void write_message(std::ostream & os, const message & msg, smtp_extensions_bitset extensions = {});

	//std::string sign_mail(EVP_PKEY * pkey, X509 * x509, std::string_view msg_body);
}
