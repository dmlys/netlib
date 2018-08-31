#include <ext/netlib/mail/simple.hpp>
#include <ext/netlib/socket_stream.hpp>
#include <ext/netlib/smtp.hpp>

#include <ext/netlib/write_string.hpp>
#include <ext/netlib/mime/encode_header_parameter.hpp>
#include <ext/netlib/mime/encode_mail_body.hpp>
#include <ext/netlib/mail/wellknown_headers.hpp>

#include <ext/Errors.hpp>
#include <ext/library_logger/logging_macros.hpp>

#include <boost/uuid/uuid.hpp> // for mime boundaries
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace ext::netlib::mail::simple
{
	void send_mail(const message & msg, const send_params & sp, ext::library_logger::logger * log)
	{
		ext::netlib::socket_stream sock;
		smtp_session ses {sock, log};
		sock.connect(sp.smtp_addr, sp.smtp_service);

		if (not sock)
		{
			auto err_msg = "SMTP connection(" + sp.smtp_addr + ":" + sp.smtp_service + ") failure: ";
			err_msg += ext::FormatError(sock.last_error());
			ses.throw_smtp_exception(err_msg);
		}

		std::string client_name = "[" + sock.sock_address() + "]";
		if (sp.smtp_startssl)
			establish_connection_starttls(ses, client_name);
		else
			establish_connection(ses, client_name);

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
		write_message(ses.sock(), msg, ses.extensions());
		end_data(ses);
		quit_connection(ses);
	}


	static void write_attachment(std::ostream & os, const mail_attachment & attachment, smtp_extensions_bitset extensions)
	{
		write_string(os, "Content-Type: application/octet-stream\r\n");
		write_string(os, "Content-Transfer-Encoding: base64\r\n");

		auto prefix = ext::as_literal("Content-Disposition: attachment; ");
		write_string(os, prefix);

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
		using namespace ext::netlib::mail::headers;
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
		os << mime_version();

		write_message_body(os, msg, extensions);

		//if (msg.cert_path.empty())
		//	write_message(os, msg);
		//else {
		//	std::string msg_body;
		//	auto dev = boost::iostreams::back_inserter(msg_body);
		//	write_message(dev, msg);
		//	sing_body(msg_body, msg);
		//	os << msg_body;
		//}
	}
}
