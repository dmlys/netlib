#include <ext/net/mail/simple.hpp>
#include <ext/net/socket_stream.hpp>
#include <ext/net/smtp.hpp>

#include <ext/net/write_string.hpp>
#include <ext/net/mime/encode_header_parameter.hpp>
#include <ext/net/mime/encode_mail_body.hpp>
#include <ext/net/mail/wellknown_headers.hpp>

#include <ext/errors.hpp>
#include <ext/log/logging_macros.hpp>

#include <boost/uuid/uuid.hpp> // for mime boundaries
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>


namespace ext::net::mail::simple
{
	void send_mail(const message & msg, const send_params & sp, ext::log::logger * log)
	{
		ext::net::socket_stream sock;
		smtp_session ses {sock, log};
		
		try
		{
			sock.exceptions(std::ios_base::badbit | std::ios_base::failbit);
			
			sock.connect(sp.smtp_addr, sp.smtp_service);
			std::string client_name = "[" + sock.sock_address() + "]";
			
		#ifdef EXT_ENABLE_OPENSSL
			if (sp.smtp_startssl)
				establish_connection_starttls(ses, client_name);
			else
				establish_connection(ses, client_name);
		#else
			establish_connection(ses, client_name);
		#endif
	
			if (sp.auth_login)
				authenticate_simple(ses, sp.auth_user, sp.auth_password);
	
			mail_from(ses, msg.from);
			for (auto & addr : msg.recipients)
				rcpt_to(ses, addr);
			
			for (auto & addr : msg.cc_recipients)
				rcpt_to(ses, addr);
			
			for (auto & addr : msg.bcc_recipients)
				rcpt_to(ses, addr);
	
			start_data(ses);
			write_message(sock, msg, ses.extensions());
			
			end_data(ses);
			quit_connection(ses);
			
			sock.exceptions(std::ios_base::iostate(0));
			sock.close();
		}
		catch (std::ios_base::failure & ex)
		{
			sock.exceptions(std::ios_base::iostate(0));
			
			auto addr_str = sp.smtp_addr + ":" + sp.smtp_service;
			auto err_msg = "SMTP connection(" + addr_str + ") failure: ";
			err_msg += ext::format_error(sock.last_error());
			ses.throw_smtp_exception(err_msg);
		}
	}

	static void write_attachment(std::ostream & os, const mail_attachment & attachment, smtp_extensions_bitset extensions)
	{
		write_string(os, "Content-Type: application/octet-stream\r\n");
		write_string(os, "Content-Transfer-Encoding: base64\r\n");

		auto prefix = ext::str_view("Content-Disposition: attachment; ");
		write_string(os, prefix);

		if (not attachment.name.empty())
			mime::encode_header_parameter_folded(os, prefix.size(), mime::MailDefaultLineSize, "filename", attachment.name);

		write_string(os, "\r\n\r\n");

		mime::encode_base64_mail_body(os, 0, mime::MailDefaultLineSize, attachment.content);
		write_string(os, "\r\n");
	}

	static void write_single_body(std::ostream & os, const message & msg, smtp_extensions_bitset extensions)
	{
		using namespace std::literals;
		
		write_string(os, "Content-Type: " + msg.content_type + "; charset=utf-8\r\n");
		if (msg.force_encoding)
		{
			write_string(os, "Content-Transfer-Encoding: "s + to_string(msg.body_encoding) + "\r\n");
			write_string(os, "\r\n");

			mime::encode_mail_body(os, msg.body_encoding, msg.body);
			write_string(os, "\r\n");
		}
		else
		{
			auto required_encoding = mime::estimate_body_encoding(msg.body, extensions);
			auto encoding = std::max(required_encoding, msg.body_encoding);

			write_string(os, "Content-Transfer-Encoding: "s + to_string(encoding) + "\r\n");
			write_string(os, "\r\n");
			mime::encode_mail_body(os, encoding, msg.body);
			write_string(os, "\r\n");
		}

	}

	static std::string generate_mime_bounary()
	{
		auto uuid = to_string(boost::uuids::random_generator()());
		return "==" + uuid;
	}

	static void write_multipart_body(std::ostream & os, const message & msg, smtp_extensions_bitset extensions)
	{
		std::string boundary = generate_mime_bounary();

		/// шапка multipart/mixed
		print_header(os, headers::mime_version());
		write_string(os, "Content-Type: multipart/mixed; boundary=\"");
		write_string(os, boundary);
		write_string(os, "\"\r\n");

		write_string(os, "\r\nThis is a multi-part message in MIME format.\r\n");

		boundary.insert(0, "--");

		write_string(os, boundary);
		write_string(os, "\r\n");

		/// теперь нужно писать собственно составные части
		write_single_body(os, msg, extensions);
		write_string(os, boundary);

		for (const auto & a : msg.attachments)
		{
			write_string(os, "\r\n");
			write_attachment(os, a, extensions);
			write_string(os, boundary);
		}

		write_string(os, "--\r\n");
	}

	static void write_message_body(std::ostream & os, const message & msg, smtp_extensions_bitset extensions)
	{
		if (msg.attachments.empty())
			write_single_body(os, msg, extensions);
		else
			write_multipart_body(os, msg, extensions);
	}

	void write_message(std::ostream & os, const message & msg, smtp_extensions_bitset extensions)
	{
		using namespace ext::net::mail::headers;
		os << date() << from(msg.from);

		if (not msg.reply_to.empty())
			os << reply_to(msg.reply_to);

		for (const auto & rcp : msg.recipients)
			os << to(rcp);

		for (const auto & rcp : msg.cc_recipients)
			os << cc(rcp);

		for (const auto & rcp : msg.bcc_recipients)
			os << bcc(rcp);

		os << subject(msg.subject);

#ifdef EXT_ENABLE_OPENSSL
		if (msg.private_key)
		{
			std::ostringstream ostr;
			write_message_body(ostr, msg, extensions);
			auto msg_body = ostr.str();
			msg_body = sign_email(msg.private_key.get(), msg.x509.get(), msg.additional_certs.get(), msg_body, msg.sign_detached);
			os << msg_body;
		}
		else
#endif
		write_message_body(os, msg, extensions);

	}

} // ext::net::mail::simple
