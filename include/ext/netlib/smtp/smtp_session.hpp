#pragma once
#include <ostream>
#include <istream>
#include <string>
#include <string_view>

#include <ext/config.hpp>
#include <ext/itoa.hpp>
#include <ext/library_logger/logger.hpp>
#include <ext/netlib/socket_stream.hpp>
#include <ext/netlib/smtp/smtp_extensions.hpp>

namespace ext::netlib::smtp
{
	class smtp_session_exception : public std::runtime_error
	{
	public:
		smtp_session_exception(const std::string & err_msg) :
			std::runtime_error(err_msg) {}
	};

	/// ��������� smtp ����� � line �� code, delim(������ ������ ����� ����: ������, �����, ...) � �������
	/// ��������� ������� ������ ������ � ������ �������� ������ - � rest ����� ���������� line.
	/// �������� parse_smtp_resonse(line, code, delim, line);
	bool parse_response(std::string_view line, int & code, char & delim, std::string_view & rest);
	bool parse_response(std::string_view line, int & code, char & delim, std::string & rest);

	/// ��������� � ��������� smtp ����� � code, delim(������ ������ ����� ����: ������, �����, ...) � �������
	/// ���� �� ���������� ��������� - ������������� failbit � is
	std::istream & parse_response(std::istream & is, int & code, char & delim, std::string & rest);
	
	/// ����� �������������� SMTP �������� ����������
	using extensions_set = smtp_extensions_bitset;

	/// ��������������� ����� ��� ������� � �������� �� ��������� smtp
	/// �������� �������/������ �������/������� � �������� ext::library_logger::logger
	/// ������������� ������� ������ ��� ���������/�������� ������� �� ������
	class smtp_session
	{
	private:
		ext::library_logger::logger * m_log = nullptr;
		socket_stream * m_sock = nullptr;
		std::string m_respline;
		extensions_set m_extensions;

	public:
		void set_logger(ext::library_logger::logger * logger) { m_log = logger; }
		auto get_logger() const { return m_log; }

	public:
		/// ���������� ������ � �������: 'Expected <wanted_code>, got "<respline>"'
		static std::string create_errmsg(int code, char delim, std::string_view rest, int wanted_code);

		BOOST_NORETURN void throw_smtp_exception(const std::string & errmsg);
		BOOST_NORETURN void throw_bad_response(const std::string & badresp);
		BOOST_NORETURN void throw_bad_response(int code, char delim, std::string_view rest, int wanted_code);

	public:
		      extensions_set & extensions()       { return m_extensions; }
		const extensions_set & extensions() const { return m_extensions; }
		       socket_stream & sock()             { return *m_sock; }

	public:		
		void log_send(std::string_view send_line);
		void log_recv(std::string_view recv_line);

	public:
		/// �������� ��� ���������
		static bool is_newline(char ch) { return ch == '\r' || ch == '\n'; }
		/// ������� \r, \n � ����� ������,
		/// ���������� boost::trim_right(line, is_newline)
		static std::string_view & choprn(std::string_view & line);
		static std::string      & choprn(std::string      & line);
		
		/// ��������� ����� �� m_sock, ������� \r, \n � ����� ������
		/// �������� ������ ������� log_recv
		std::string & readline();

		/// ��������� � ������ �����
		/// ���� ���������� �� ������� ��� ��� �� ����� wanted_code - ������� smtp_session_exception
		/// ������������ multiline ������, �������� ��� � ������� ehlo
		void process_answer(int wanted_code);

		/// �������� ������, ���������� ������ � m_sock.
		void send(std::string_view command);

		/// �������� ������, ���������� ������ � m_sock,
		/// ��������� ����� � ��������� ��� ��� ����� wanted_code
		void send(std::string_view command, int wanted_code);

	public:
		smtp_session(const smtp_session &) = delete;
		smtp_session & operator =(const smtp_session &) = delete;

	public:
		smtp_session(socket_stream & sock)
			: m_log(nullptr), m_sock(&sock)
		{
			m_sock->self_tie(true);
		}

		smtp_session(socket_stream & sock, ext::library_logger::logger * conversation_log)
			: smtp_session(sock)
		{
			set_logger(conversation_log);
		}
	};
} // namespace ext::netlib::smtp

namespace ext::netlib
{
	using smtp::smtp_session;
}
