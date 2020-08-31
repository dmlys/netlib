#pragma once
#include <memory>
#include <utility> // for std::exchange
#include <streambuf>
#include <ext/iostreams/streambuf.hpp>

namespace ext::net
{
	/// Базовый класс для построения socket_streambuf классов.
	/// Реализует буферизацию, непосредственно операции работы с сокетами реализуется наследником
	/// при открытии/подключении класс наследник должен вызвать функцию init_buffers,
	/// в которой по желанию может указать желаемый размер буфера по-умолчанию
	/// 
	/// умеет:
	/// * установка пользовательского буфера, буфер делиться пополам на ввод/вывод(подробное смотри соотв метод)
	///   класс всегда буферизованн, минимальный размер буфера - 128 байт
	///   если пользователь попытается убрать буфер или предоставить слишком маленький буфер - класс откатится на буфер по умолчанию
	/// * входящая область по умолчанию автоматически синхронизируется с исходящей. Подобно std::ios::tie
	///   как только входящий буфер исчерпан, прежде чем он будет заполнен из сокета - исходящий буфер будет сброшен в сокет
	class socket_streambuf_base : public ext::streambuf
	{
	private:
		typedef ext::streambuf base_type;

	private:
		char_type * m_input_buffer = nullptr;
		char_type * m_output_buffer = nullptr;
		unsigned    m_input_buffer_size = 0;
		unsigned    m_output_buffer_size = 0;
		
		bool m_tie_io = true;
		bool m_default_internal_buffer = false;
		bool m_own_input_buffer = false;
		bool m_own_output_buffer = false;

	public:
		static constexpr std::size_t default_buffer_size = 2 * 4096;
		static constexpr std::size_t minimum_buffer_size = 128;

	private:
		std::size_t write_all(const char_type * data, std::size_t count);
		std::size_t read_all(char_type * data, std::size_t count);

	protected:
		/// если буфер не установлен посредством вызова setbuf
		/// аллоцирует внутренние буферы размером buffer_size,
		/// буфер делится пополам для input/output областей
		/// в любом случае вызывает set_buffers
		/// buffer_size is clamped(minimum_buffer_size, ..., INT_MAX)
		void init_buffers(std::size_t buffer_size = default_buffer_size);
		/// инициализирует внутренние буферы, даже если они были установленны посредством вызова setbuf,
		/// если буферы по факту внутренние - оставляет их как есть
		void reset_buffers(std::size_t buffer_size = default_buffer_size);
		/// устанавливает get/put buffer areas. Буферы никак не синхронизируется с сокетом
		void set_buffers() noexcept;

		// input
		std::streamsize xsgetn(char_type * ptr, std::streamsize n) override;
		std::streamsize showmanyc() override = 0; // should be implemented in derived class
		int_type underflow() override;

		// output
		std::streamsize xsputn(const char_type * ptr, std::streamsize n) override;
		int_type overflow(int_type ch = traits_type::eof()) override;
		int sync() override;
	
	protected:
		virtual std::size_t read_some(char_type * data, std::size_t count) = 0;
		virtual std::size_t write_some(const char_type * data, std::size_t count) = 0;
		
	public:
		/// устанавливает пользовательский буфер, не владеет пользовательским буфером и не освобождает его.
		/// Если buffer == nullptr - откатывается на дефолтный внутренний буфер.
		/// Если or size < minimum_buffer_size - бросает std::logic_error
		/// Таким образом класс всегда буферизованн.
		///
		/// Вызов для уже открытого объекта - undefined behavior, скорее всего ничего хорошего.
		/// Заданный буфер делиться поплам между input и output областей.
		virtual std::streambuf * setbuf(char_type * buffer, std::streamsize size) override;

		/// устанавливает пользовательский буфер, владение задается флагом owning.
		/// Если buffer == nullptr - откатывается на дефолтный внутренний буфер.
		/// Если or input_size < minimum_buffer_size or output_size < minimum_buffer_size - бросает std::logic_error
		///
		/// Вызов для уже открытого объекта - undefined behavior, скорее всего ничего хорошего.
		/// Заданный буфер делиться между input и output областей в соответствии с input_size и output_size.
		/// Подразумевается что общий размер буфера - input_size + output_size
		virtual std::streambuf * setbuf(bool owning, char_type * buffer, std::streamsize input_size, std::streamsize output_size);

		/// устанавливает пользовательский буфер, владение задается флагом owning.
		/// Если input_buffer or output_buffer == nullptr or input_size < minimum_buffer_size or output_size < minimum_buffer_size - бросает std::logic_error
		///
		/// Вызов для уже открытого объекта - undefined behavior, скорее всего ничего хорошего.
		/// Заданный буфер делиться между input и output областей в соответствии с input_size и output_size.
		/// Подразумевается что общий размер буфера - input_size + output_size
		virtual std::streambuf * setbuf(bool input_owning, char_type * input_buffer, std::streamsize input_size,
		                                bool output_owning, char_type * output_buffer, std::streamsize output_size);

	public:
		auto getbuf() noexcept -> std::pair<char *, char *>                    { return {m_input_buffer, m_input_buffer + m_input_buffer_size}; }
		auto getbuf() const noexcept -> std::pair<const char *, const char *>  { return {m_input_buffer, m_input_buffer + m_input_buffer_size}; }

		auto putbuf() noexcept -> std::pair<char *, char *>                    { return {m_output_buffer, m_output_buffer + m_output_buffer_size}; }
		auto putbuf() const noexcept -> std::pair<const char *, const char *>  { return {m_output_buffer, m_output_buffer + m_output_buffer_size}; }

	public:
		/// синхронизация входящего потока с исходящим, по умолчанию включена
		bool self_tie()   const noexcept { return m_tie_io; }
		bool self_tie(bool tie) noexcept { return std::exchange(m_tie_io, tie); }

	protected:
		socket_streambuf_base() = default;
		~socket_streambuf_base();

		socket_streambuf_base(const socket_streambuf_base &) = delete;
		socket_streambuf_base & operator=(const socket_streambuf_base &) = delete;
		
		socket_streambuf_base(socket_streambuf_base && right) noexcept;
		socket_streambuf_base & operator=(socket_streambuf_base && right) noexcept;

		void swap(socket_streambuf_base & right) noexcept;
	};
}
