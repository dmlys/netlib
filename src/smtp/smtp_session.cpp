#include <ext/net/smtp/smtp_session.hpp>
#include <ext/log/logging_macros.hpp>

namespace ext::net::smtp
{
	BOOST_NORETURN void smtp_session::throw_smtp_exception(const std::string & errmsg)
	{
		EXTLOG_ERROR(m_log, errmsg);
		throw smtp_session_exception(errmsg);
	}

	BOOST_NORETURN void smtp_session::throw_bad_response(const std::string & badresp)
	{
		auto err_msg = "failed to parse response: " + badresp;
		EXTLOG_ERROR(m_log, err_msg);
		throw smtp_session_exception(err_msg);
	}

	BOOST_NORETURN void smtp_session::throw_bad_response(int code, char delim, std::string_view rest, int wanted_code)
	{
		auto err_msg = create_errmsg(code, delim, rest, wanted_code);
		EXTLOG_ERROR(m_log, err_msg);
		throw smtp_session_exception(err_msg);
	}

	std::string smtp_session::create_errmsg(int code, char delim, std::string_view rest, int wanted_code)
	{
		std::string err_msg = "Expected ";

		itoa_buffer<int> buffer;
		err_msg += ext::itoa(wanted_code, buffer);

		err_msg += ", got \"";

		err_msg += ext::itoa(code, buffer);
		err_msg += delim;
		err_msg += rest;

		err_msg += '"';

		return err_msg;
	}

	void smtp_session::log_send(std::string_view send_line)
	{
		EXTLOG_INFO(m_log, "C: " << send_line);
	}

	void smtp_session::log_recv(std::string_view recv_line)
	{
		EXTLOG_INFO(m_log, "S: " << recv_line);
	}

	bool parse_response(std::string_view line, int & code, char & delim, std::string_view & rest)
	{
		char * stopped;
		const char * str = line.data();
		const char * last = str + line.size();
		if (*--last != '\r') ++last; //step back if last character is \r

		errno = 0;
		long val = std::strtol(str, &stopped, 10);
		if (errno != 0) return false;
		if (stopped == last) return false;

		code = static_cast<int>(val);
		delim = *stopped++;
		rest = std::string_view(stopped, last - stopped);
		return true;
	}

	bool parse_response(std::string_view line, int & code, char & delim, std::string & rest)
	{
		std::string_view rest_view;
		bool result = parse_response(line, code, delim, rest_view);
		if (not result) return result;
		
		rest.assign(rest_view.data(), rest_view.size());
		return result;
	}

	std::istream & parse_response(std::istream & is, int & code, char & delim, std::string & rest)
	{
		std::getline(is, rest);
		if (!parse_response(rest, code, delim, rest))
			is.setstate(std::ios::failbit);

		return is;
	}

	std::string_view & smtp_session::choprn(std::string_view & line)
	{
		auto * first = line.data();
		auto * last = first + line.size();

		// trim left
		while (first != last and is_newline(*first)) ++first;

		// trim right
		--last;
		while (first != last and is_newline(*last))  --last;
		++last;

		return line = std::string_view(first, last - first);
	}

	std::string & smtp_session::choprn(std::string & line)
	{
		auto * first = line.data();
		auto * last = first + line.size();

		// trim left
		while (first != last and is_newline(*first)) ++first;

		// trim right
		--last;
		while (first != last and is_newline(*last))  --last;
		++last;

		return line.assign(first, last);
	}

	void smtp_session::process_answer(int wanted_code)
	{
		int code = 0;
		char delim = 0;

		do {
			readline();
			bool parsed = smtp::parse_response(m_respline, code, delim, m_respline);

			if (!parsed)             throw_bad_response(m_respline);
			if (code != wanted_code) throw_bad_response(code, delim, m_respline, wanted_code);

		} while (delim != ' ');	
	}

	std::string & smtp_session::readline()
	{
		std::getline(*m_sock, m_respline);
		choprn(m_respline);
		log_recv(m_respline);
		return m_respline;
	}

	void smtp_session::send(std::string_view command)
	{
		auto req = choprn(command);
		log_send(req);

		*m_sock << req << "\r\n";
	}

	void smtp_session::send(std::string_view command, int wanted_code)
	{
		send(command);
		process_answer(wanted_code);
	}
	
}
