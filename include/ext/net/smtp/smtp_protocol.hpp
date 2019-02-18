#pragma once
#include <string_view>
#include <ext/is_string.hpp>
#include <ext/net/smtp/smtp_session.hpp>

namespace ext::net::smtp
{
	/// все методы ожидают что smtp_session уже содержит подключенный сокет

	/************************************************************************/
	/*                   SMTP connection management                         */
	/************************************************************************/

	/// разбирает ответ от команды ehlo. Заполняет ses.extensions() по ответу
	void parse_ehlo_response(smtp_session & ses);

	/// устанавливает незащищенное соединение, ожидает строку ответа с 220 кодом,
	/// шлет ehlo и ожидает 250 код ответа.
	/// client_name - имя клиента, это обязательный параметр
	/// хотя многие сервера позволяют его пропустить, некоторые требуют его
	/// в случае ошибки кидает smtp_session_exception
	void establish_connection(smtp_session & ses, std::string_view client_name);

#if EXT_ENABLE_OPENSSL
	/// устанавливает незащищенное соединение, ожидает строку ответа с 220 кодом,
	/// шлет ehlo и ожидает 250 код ответа.
	/// после шлет starttls, повышает соединение до защищенного,
	/// client_name - имя клиента, это обязательный параметр
	/// хотя многие сервера позволяют его пропустить, некоторые требуют его
	/// в случае ошибки кидает smtp_session_exception
	void establish_connection_starttls(smtp_session & ses, std::string_view client_name);
	void establish_connection_starttls(smtp_session & ses, std::string_view client_name, const SSL_CTX * method);
	void establish_connection_starttls(smtp_session & ses, std::string_view client_name, const SSL_METHOD * method);
#endif

	/// шлет quit, и ожидает 221 код ответа
	/// в случае ошибки returns false
	bool quit_connection(smtp_session & ses);


	/************************************************************************/
	/*                   SMTP authentication                                */
	/************************************************************************/

	/// выполняет аутентификацию методом auth login или auth plain.
	/// если оба недоступны - кидает smtp_session_exception.
	/// в случае ошибок - кидает smtp_session_exception.
	void authenticate_simple(smtp_session & ses, std::string_view user, std::string_view pass);

	/************************************************************************/
	/*                       SMTP envelope                                  */
	/************************************************************************/

	/// вспомогательный метод для извлечения email адреса из строки вида:
	/// User Name <email.addr@domaim>
	/// <email.addr@domaim>
	/// 
	/// если строка вида email.addr@domaim, она будет возвращена как есть
	std::string_view extract_addr(std::string_view str);

	/// посылает заданную команду @command: @addr и ожидает заданный ответ
	/// в случае ошибок кидает smtp_session_exception
	/// 
	/// адрес может быть в формате:
	///  * email.addr@domain
	///  * <email.addr@domain>
	///  * User Name <email.addr@domain>
	/// во всех случаях только <email.addr@domain> будет послано на сервер
	void send_address_command(smtp_session & ses, std::string_view command, std::string_view addr, int wanted_code);
	
	/// посылает команду mail from: <addr>
	/// ожидает код ответа 250
	/// в случае ошибок кидает smtp_session_exception
	/// 
	/// адрес может быть в формате:
	///  * email.addr@domain
	///  * <email.addr@domain>
	///  * User Name <email.addr@domain>
	/// во всех случаях только <email.addr@domain> будет послано на сервер
	inline void mail_from(smtp_session & ses, std::string_view addr) { return send_address_command(ses, "mail from", addr, 250); }

	/// посылает команду rcpt to: <addr> для каждого переданного адреса в addr_or_addr_range
	/// ожидает код ответа 250
	/// в случае ошибок кидает smtp_session_exception
	/// 
	/// адрес может быть в формате:
	///  * email.addr@domain
	///  * <email.addr@domain>
	///  * User Name <email.addr@domain>
	/// во всех случаях только <email.addr@domain> будет послано на сервер
	inline void rcpt_to(smtp_session & ses, std::string_view addr)   { return send_address_command(ses, "rcpt to", addr, 250); }

	/// reset команда - сбрасывает текущее сообщение, и весь envelope(mail from, rcpt to параметры)
	inline void reset(smtp_session & ses) { ses.send("rset", 250); }

	/// посылает команду data, ожидает код ответа 354,
	/// в случае ошибок - smtp_session_exception
	/// после выполнения следует послать сообщения в корректном формате в ses.sock()
	/// и вызвать end_data
	void start_data(smtp_session & ses);

	/// завершает отправку сообщения, посылая \r\n.\r\n
	/// и ожидая код ответа 250
	/// в случае ошибок - smtp_session_exception
	/// вызвать после вызова start_data и выдачи сообщения в ses.sock()
	void end_data(smtp_session & ses);
}

