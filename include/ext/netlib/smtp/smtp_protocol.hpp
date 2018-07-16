#pragma once
#include <string_view>
#include <ext/is_string.hpp>
#include <ext/netlib/smtp/smtp_session.hpp>

namespace ext::netlib::smtp
{
	/// ��� ������ ������� ��� smtp_session ��� �������� ������������ �����

	/************************************************************************/
	/*                   SMTP connection management                         */
	/************************************************************************/

	/// ��������� ����� �� ������� ehlo. ��������� ses.extensions() �� ������
	void parse_ehlo_response(smtp_session & ses);

	/// ������������� ������������ ����������, ������� ������ ������ � 220 �����,
	/// ���� ehlo � ������� 250 ��� ������.
	/// client_name - ��� �������, ��� ������������ ��������
	/// ���� ������ ������� ��������� ��� ����������, ��������� ������� ���
	/// � ������ ������ ������ smtp_session_exception
	void establish_connection(smtp_session & ses, std::string_view client_name);

#if EXT_ENABLE_OPENSSL
	/// ������������� ������������ ����������, ������� ������ ������ � 220 �����,
	/// ���� ehlo � ������� 250 ��� ������.
	/// ����� ���� starttls, �������� ���������� �� �����������,
	/// client_name - ��� �������, ��� ������������ ��������
	/// ���� ������ ������� ��������� ��� ����������, ��������� ������� ���
	/// � ������ ������ ������ smtp_session_exception
	void establish_connection_starttls(smtp_session & ses, std::string_view client_name);
	void establish_connection_starttls(smtp_session & ses, std::string_view client_name, const SSL_CTX * method);
	void establish_connection_starttls(smtp_session & ses, std::string_view client_name, const SSL_METHOD * method);
#endif

	/// ���� quit, � ������� 221 ��� ������
	/// � ������ ������ returns false
	bool quit_connection(smtp_session & ses);


	/************************************************************************/
	/*                   SMTP authentication                                */
	/************************************************************************/

	/// ��������� �������������� ������� auth login ��� auth plain.
	/// ���� ��� ���������� - ������ smtp_session_exception.
	/// � ������ ������ - ������ smtp_session_exception.
	void authenticate_simple(smtp_session & ses, std::string_view user, std::string_view pass);

	/************************************************************************/
	/*                       SMTP envelope                                  */
	/************************************************************************/

	/// ��������������� ����� ��� ���������� email ������ �� ������ ����:
	/// User Name <email.addr@domaim>
	/// <email.addr@domaim>
	/// 
	/// ���� ������ ���� email.addr@domaim, ��� ����� ���������� ��� ����
	std::string_view extract_addr(std::string_view str);

	/// �������� �������� ������� @command: @addr � ������� �������� �����
	/// � ������ ������ ������ smtp_session_exception
	/// 
	/// ����� ����� ���� � �������:
	///  * email.addr@domain
	///  * <email.addr@domain>
	///  * User Name <email.addr@domain>
	/// �� ���� ������� ������ <email.addr@domain> ����� ������� �� ������
	void send_address_command(smtp_session & ses, std::string_view command, std::string_view addr, int wanted_code);
	
	/// �������� ������� mail from: <addr>
	/// ������� ��� ������ 250
	/// � ������ ������ ������ smtp_session_exception
	/// 
	/// ����� ����� ���� � �������:
	///  * email.addr@domain
	///  * <email.addr@domain>
	///  * User Name <email.addr@domain>
	/// �� ���� ������� ������ <email.addr@domain> ����� ������� �� ������
	inline void mail_from(smtp_session & ses, std::string_view addr) { return send_address_command(ses, "mail from", addr, 250); }

	/// �������� ������� rcpt to: <addr> ��� ������� ����������� ������ � addr_or_addr_range
	/// ������� ��� ������ 250
	/// � ������ ������ ������ smtp_session_exception
	/// 
	/// ����� ����� ���� � �������:
	///  * email.addr@domain
	///  * <email.addr@domain>
	///  * User Name <email.addr@domain>
	/// �� ���� ������� ������ <email.addr@domain> ����� ������� �� ������
	inline void rcpt_to(smtp_session & ses, std::string_view addr)   { return send_address_command(ses, "rcpt to", addr, 250); }

	/// reset ������� - ���������� ������� ���������, � ���� envelope(mail from, rcpt to ���������)
	inline void reset(smtp_session & ses) { ses.send("rset", 250); }

	/// �������� ������� data, ������� ��� ������ 354,
	/// � ������ ������ - smtp_session_exception
	/// ����� ���������� ������� ������� ��������� � ���������� ������� � ses.sock()
	/// � ������� end_data
	void start_data(smtp_session & ses);

	/// ��������� �������� ���������, ������� \r\n.\r\n
	/// � ������ ��� ������ 250
	/// � ������ ������ - smtp_session_exception
	/// ������� ����� ������ start_data � ������ ��������� � ses.sock()
	void end_data(smtp_session & ses);
}

