#pragma once
#include <ostream>
#include <istream>
#include <string>
#include <string_view>

#include <ext/config.hpp>
#include <ext/itoa.hpp>
#include <ext/log/logger.hpp>
#include <ext/net/socket_stream.hpp>
#include <ext/net/smtp/smtp_extensions.hpp>

namespace ext::net::smtp
{
	class smtp_session_exception : public std::runtime_error
	{
	public:
		smtp_session_exception(const std::string & err_msg) :
			std::runtime_error(err_msg) {}
	};

	/// разбирает smtp ответ в line на code, delim(первый символ после кода: пробел, дефис, ...) и остаток
	/// поскольку остаток всегда меньше и правее исходной строки - в rest можно передавать line.
	/// например parse_smtp_resonse(line, code, delim, line);
	bool parse_response(std::string_view line, int & code, char & delim, std::string_view & rest);
	bool parse_response(std::string_view line, int & code, char & delim, std::string & rest);

	/// считывает и разбирает smtp ответ в code, delim(первый символ после кода: пробел, дефис, ...) и остаток
	/// если не получилось разобрать - устанавливает failbit в is
	std::istream & parse_response(std::istream & is, int & code, char & delim, std::string & rest);
	
	/// набор поддерживаемых SMTP сервером расширений
	using extensions_set = smtp_extensions_bitset;

	/// вспомогательный класс для общения с сервером по протоколу smtp
	/// логирует запросы/ответы клиента/сервера в заданный ext::log::logger
	/// предоставляет базовые методы для получения/парсинга ответов от севера
	class smtp_session
	{
	private:
		ext::log::logger * m_log = nullptr;
		socket_stream * m_sock = nullptr;
		std::string m_respline;
		extensions_set m_extensions;

	public:
		void set_logger(ext::log::logger * logger) { m_log = logger; }
		auto get_logger() const { return m_log; }

	public:
		/// возвращает строку в формате: 'Expected <wanted_code>, got "<respline>"'
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
		/// предикат для тримминга
		static bool is_newline(char ch) { return ch == '\r' || ch == '\n'; }
		/// удаляет \r, \n с конца строки,
		/// аналогично boost::trim_right(line, is_newline)
		static std::string_view & choprn(std::string_view & line);
		static std::string      & choprn(std::string      & line);
		
		/// считывает ответ из m_sock, удаляет \r, \n в конце строки
		/// логирует строку вызовом log_recv
		std::string & readline();

		/// считывает и парсит ответ
		/// если распарсить не удалось или код не равен wanted_code - бросает smtp_session_exception
		/// поддерживает multiline ответы, например как в команде ehlo
		void process_answer(int wanted_code);

		/// логирует запрос, отправляет запрос в m_sock.
		void send(std::string_view command);

		/// логирует запрос, отправляет запрос в m_sock,
		/// считывает ответ и проверяет что код равен wanted_code
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

		smtp_session(socket_stream & sock, ext::log::logger * conversation_log)
			: smtp_session(sock)
		{
			set_logger(conversation_log);
		}
	};
} // namespace ext::net::smtp

namespace ext::net
{
	using smtp::smtp_session;
}
