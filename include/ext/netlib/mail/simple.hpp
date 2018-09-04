#pragma once
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include <ext/library_logger/logger.hpp>
#include <ext/netlib/mime/mail_encoding.hpp>
#include <ext/netlib/smtp/smtp_extensions.hpp>

namespace ext::netlib::mail::simple
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

		//std::string cert_path;
		//std::string cert_passwd;
		//bool sign_detached = true;
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
}
