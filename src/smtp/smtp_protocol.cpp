#include <ext/functors/ctpred.hpp>
#include <ext/strings/aci_string.hpp>
#include <ext/log/logging_macros.hpp>
#include <ext/base64.hpp>

#include <ext/net/smtp/smtp_protocol.hpp>

#ifdef EXT_ENABLE_OPENSSL
#	include <openssl/ssl.h>
#endif

namespace ext::net::smtp
{
	static bool contains(std::string_view respline, std::string_view test)
	{
		auto * first = respline.data();
		auto * last = first + respline.size();
		auto * f_first = test.data();
		auto * f_last = f_first + test.size();

		auto res = std::search(first, last, f_first, f_last, ext::aci_char_traits::eq);
		return res != last;
	}

	static bool starts_with(std::string_view respline, std::string_view test)
	{
		if (respline.size() < test.size()) return false;

		auto * first = respline.data();
		auto * last = first + test.size();
		auto * f_first = test.data();

		return std::equal(first, last, f_first, ext::aci_char_traits::eq);
	}

	static auto operator +(const std::string & str, std::string_view view)
	{
		std::string result;
		result += str;
		result += view;

		return result;
	}

	static auto operator +(const char * str, std::string_view view)
	{
		std::string result;
		result += str;
		result += view;

		return result;
	}

	/************************************************************************/
	/*                   SMTP connection management                         */
	/************************************************************************/
	static void parse_extensions(std::string_view respline, extensions_set & extensions)
	{
		ext::ctpred::equal_to<ext::aci_string> eq;
		if (eq(respline, "STARTTLS")) extensions[starttls] = true;
		if (eq(respline, "CHUNKING")) extensions[chunking] = true;
		if (eq(respline, "8BITMIME")) extensions[bit8_mime] = true;
		if (eq(respline, "BINARYMIME")) extensions[binary_mime] = true;
		if (eq(respline, "SMTPUTF8")) extensions[smtp_utf8] = true;

		if (starts_with(respline, "AUTH"))
		{			
			extensions[login_auth] = contains(respline, "LOGIN");
			extensions[login_plain] = contains(respline, "PLAIN");
		}
	}

	void parse_ehlo_response(smtp_session & ses)
	{
		auto & extensions = ses.extensions();
		int code = 0;
		char delim = 0;
		bool parsed;

		while (delim != ' ')
		{
			auto & line = ses.readline();

			parsed = parse_response(line, code, delim, line);
			if (not parsed)  ses.throw_bad_response(line);
			if (code != 250) ses.throw_bad_response(code, delim, line, 250);

			parse_extensions(line, extensions);
		}
	}

	void establish_connection(smtp_session & ses, std::string_view client_name)
	{
		// первый ответ сразу после connect
		ses.process_answer(220);
		ses.send("ehlo " + client_name);
		auto & line = ses.readline();
		
		int code = 0;
		char delim = 0;
		bool parsed = parse_response(line, code, delim, line);
		if (not parsed) ses.throw_bad_response(line);

		if (code == 250)
		{
			// считываем оставшийся ответ
			if (delim != ' ') parse_ehlo_response(ses);
			return;
		}

		// unrecognized or not implemented
		if (code != 500 && code != 502)
			ses.throw_bad_response(code, delim, line, 250);

		ses.log_send("<ehlo unrecognized or unimplemented. Trying HELO>");
		ses.send("HELO " + client_name, 220);
	}

#ifdef EXT_ENABLE_OPENSSL
	void establish_connection_starttls(smtp_session & ses, std::string_view client_name)
	{
		establish_connection_starttls(ses, client_name, SSLv23_client_method());
	}

	void establish_connection_starttls(smtp_session & ses, std::string_view client_name, SSL_CTX * ctx)
	{
		// первый ответ сразу после connect
		ses.process_answer(220);

		// здороваемся и начитываем расширения
		auto greatings_cmd = "ehlo " + client_name;
		ses.send(greatings_cmd);
		parse_ehlo_response(ses);

		if (not ses.extensions()[starttls])
			ses.throw_smtp_exception("server does not provide STARTTLS extension");

		// инициируем tls соединение
		ses.send("starttls", 220);

		ses.log_send("<ssl_start>");
		auto & sock = ses.sock();
		sock.start_ssl(ctx);
		ses.log_send("<ssl_started>");

		// начитываем расширения еще раз, они могли изменится.
		ses.send(greatings_cmd);
		parse_ehlo_response(ses);
	}

	void establish_connection_starttls(smtp_session & ses, std::string_view client_name, const SSL_METHOD * method)
	{
		// первый ответ сразу после connect
		ses.process_answer(220);

		// здороваемся и начитываем расширения
		auto greatings_cmd = "ehlo " + client_name;
		ses.send(greatings_cmd);
		parse_ehlo_response(ses);

		if (not ses.extensions()[starttls])
			ses.throw_smtp_exception("server does not provide STARTTLS extension");

		// инициируем tls соединение
		ses.send("starttls", 220);

		ses.log_send("<ssl_start>");
		auto & sock = ses.sock();
		sock.start_ssl(method);
		ses.log_send("<ssl_started>");

		// начитываем расширения еще раз, они могли изменится.
		ses.send(greatings_cmd);
		parse_ehlo_response(ses);
	}
#endif

	bool quit_connection(smtp_session & ses)
	{
		try {
			ses.send("quit", 221);
			return true;
		}
		catch (smtp_session_exception & ex) 
		{
			EXTLOG_ERROR(ses.get_logger(), "SMTP session QUIT error: " << ex.what());
			return false;
		}
	}

	/************************************************************************/
	/*                   SMTP authentication                                */
	/************************************************************************/

	void authenticate_simple(smtp_session & ses, std::string_view user, std::string_view pass)
	{
		auto & sock = ses.sock();

		if (ses.extensions()[login_auth])
		{
			std::string encoded;
			ses.send("auth login", 334);

			encoded.clear();
			ext::encode_base64(user, encoded);
			ses.log_send("<base64 encoded login>");

			sock << encoded << "\r\n";
			ses.process_answer(334);

			encoded.clear();
			ext::encode_base64(pass, encoded);
			ses.log_send("<base64 encoded password>");

			sock << encoded << "\r\n";
			ses.process_answer(235);

			return;
		}

		if (ses.extensions()[login_plain])
		{
			std::string str;
			str += '\0';
			str += user;
			str += '\0';
			str += pass;

			auto encoded = ext::encode_base64(str);
			ses.log_send("auth plain <base64 encoded loginpassword>");

			sock << "auth plain " << encoded << "\r\n";
			ses.process_answer(235);

			return;
		}

		ses.throw_smtp_exception("server does not provide AUTH LOGIN or AUTH PLAIN extension");
	}

	/************************************************************************/
	/*                       SMTP envelope                                  */
	/************************************************************************/

	/// ищет заданный символ, учитывая возможность закавычивания
	template <class Iterator>
	static Iterator find_nonquoted(Iterator first, Iterator last, char ch)
	{
		bool quoted = false;
		int  comment_level = 0;
		for (; first != last; ++first)
		{
			auto cur = *first;

			if (cur == '\\')
			{
				// skipping next char
				if (++first == last) return first;
				continue;
			}

			if (cur == '"')
			{
				quoted = not quoted;
				continue;
			}

			if (quoted) continue;

			if (cur == '(')
			{
				++comment_level;
				continue;
			}

			if (cur == ')')
			{
				--comment_level;
				continue;
			}

			if (cur == ch && comment_level == 0) return first;
		}

		return first;
	}

	std::string_view extract_addr(std::string_view str)
	{
		auto * first = str.data();
		auto * last =  first + str.size();
		std::string_view result = str;

		// мы хотим найти angle braced адрес. Если таких несколько - нас интересует последний.
		// т.е. в Name <somestr> <addr> мы хотим addr
		for (;;)
		{
			auto open = find_nonquoted(first, last, '<');
			if (open == last) break;

			auto close = find_nonquoted(++open, last, '>');
			if (close == last) break;

			result = std::string_view(open, close - open);
			first = ++close;
		}

		return result;
	}


	void send_address_command(smtp_session & ses, std::string_view command, std::string_view addr, int wanted_code)
	{		
		addr = extract_addr(addr);

		std::string cmd;
		cmd += command;
		cmd += ": <";
		cmd += addr;
		cmd += ">";
		
		ses.send(cmd, wanted_code);
	}

	void start_data(smtp_session & ses)
	{
		ses.send("data", 354);
		ses.log_send("<start data sending>");
	}

	void end_data(smtp_session & ses)
	{
		ses.log_send("<data sent>");
		ses.sock() << "\r\n.\r\n";
		ses.process_answer(250);
	}
}
