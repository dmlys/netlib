#include <cassert>
#include <climits> // for INT_MAX
#include <utility> // for std::exchange
#include <algorithm>
#include <ext/net/socket_streambuf_base.hpp>

namespace ext::net
{
	/************************************************************************/
	/*                 get/put area implementation                          */
	/************************************************************************/
	void socket_streambuf_base::init_buffers(std::size_t buffer_size /* = m_defbuffer_size */)
	{
		if (m_input_buffer)
		{
			set_buffers();
			return;
		}

		if (m_own_input_buffer)  delete [] m_input_buffer;
		if (m_own_output_buffer) delete [] m_output_buffer;
		
		m_own_input_buffer = m_own_output_buffer = false;
		m_default_internal_buffer = false;
		
		// default internal buffer
		buffer_size = std::clamp<std::size_t>(minimum_buffer_size, buffer_size, INT_MAX);
		auto buffer = std::make_unique<char_type[]>(buffer_size);
		
		m_default_internal_buffer = true;
		m_own_input_buffer = true;
		m_own_output_buffer = false;
		
		m_input_buffer = buffer.release();
		m_input_buffer_size = buffer_size / 2;
		m_output_buffer = m_input_buffer + m_input_buffer_size;
		m_output_buffer_size = m_input_buffer_size;

		set_buffers();
	}
	
	void socket_streambuf_base::reset_buffers(std::size_t buffer_size)
	{
		if (not m_default_internal_buffer)
		{
			if (m_own_input_buffer)  delete [] m_input_buffer;
			if (m_own_output_buffer) delete [] m_output_buffer;
			m_own_input_buffer = m_own_output_buffer = false;
			m_input_buffer = m_output_buffer = nullptr;
		}

		init_buffers(buffer_size);
	}

	void socket_streambuf_base::set_buffers() noexcept
	{
		assert(m_input_buffer && m_output_buffer && m_input_buffer_size && m_output_buffer_size);

		setp(m_output_buffer, m_output_buffer + m_output_buffer_size);
		setg(m_input_buffer, m_input_buffer, m_input_buffer);
	}

	std::size_t socket_streambuf_base::write_all(const char_type * data, std::size_t count)
	{
		std::size_t written = 0;
		while (count)
		{
			auto res = write_some(data, count);
			if (res <= 0) return written;

			count -= res;
			written += res;
			data += res;
		}

		return written;
	}

	std::size_t socket_streambuf_base::read_all(char_type * data, std::size_t count)
	{
		std::size_t read = 0;
		while (count)
		{
			auto res = read_some(data, count);
			if (res <= 0) return read;

			count -= res;
			read += res;
			data += res;
		}

		return read;
	}

	std::streamsize socket_streambuf_base::xsgetn(char_type * ptr, std::streamsize n)
	{
		std::size_t count = static_cast<std::size_t>(n);
		/// сначала копируем из внутреннего буфера
		std::size_t buffer_avail = egptr() - gptr();
		if (buffer_avail)
		{
			// в буфер есть столько сколько нам нужно
			if (buffer_avail >= count)
			{
				std::copy_n(gptr(), count, ptr);
				gbump(static_cast<int>(count));
				return count;
			}

			ptr = std::copy_n(gptr(), buffer_avail, ptr);
			// по факту выставляем get область пустой, поскольку мы оттуда все прочли
			gbump(static_cast<int>(buffer_avail));
			count -= buffer_avail;
		}

		if (m_tie_io && sync() == -1) // сбрасываем выходной буфер, если требуется
			return buffer_avail;      // бросить не удалось - возвращаем сколько уже прочитали

		// начитываем из сокета:
		// если нужно прочитать больше чем половина размера внутреннего буфера -
		// сразу читаем в пользовательский, иначе заполняем внутренний
		if (count >= m_input_buffer_size / 2)
			return buffer_avail + read_all(ptr, count);
		else
		{
			// заполняем внутренний буфер, но только до тех пор,
			// пока не наберем нужно кол-во символов, набрали больше - ок
			auto buf = m_input_buffer;
			std::size_t read = 0;
			while (count > read)
			{
				auto res = read_some(buf, m_input_buffer_size - read);
				if (res <= 0) break;

				buf += res;
				read += res;
			}

			// мы могли прочитать меньше чем count, если произошла ошибка, или дошли до eof
			count = std::min(count, read);
			std::copy_n(m_input_buffer, count, ptr);
			setg(m_input_buffer, m_input_buffer + count, m_input_buffer + read);
			return count + buffer_avail;
		}
	}

	auto socket_streambuf_base::underflow() -> int_type
	{
		if (m_tie_io && sync() == -1)
			return traits_type::eof();

		auto read = read_some(m_input_buffer, m_input_buffer_size);
		if (read <= 0) return traits_type::eof();

		setg(m_input_buffer, m_input_buffer, m_input_buffer + read);
		return traits_type::to_int_type(*m_input_buffer);
	}

	std::streamsize socket_streambuf_base::xsputn(const char_type * ptr, std::streamsize n)
	{
		std::size_t count = static_cast<std::size_t>(n);
		// если запрос меньше внутреннего буфера или
		// в нем уже что-то есть - пишем в буфер
		std::size_t written_though_buffer = 0;
		std::size_t buffer_avail = epptr() - pptr();
		bool write_into_buffer = count < m_output_buffer_size || buffer_avail != m_output_buffer_size;
		if (write_into_buffer)
		{
			// в буфер может поместится все
			if (buffer_avail >= count)
			{
				std::copy_n(ptr, count, pptr());
				pbump(static_cast<int>(count));
				return count;
			}

			std::copy_n(ptr, buffer_avail, pptr());
			//pbump(static_cast<int>(buffer_avail));
			ptr += buffer_avail;
			count -= buffer_avail;
			written_though_buffer = buffer_avail;

			// flush buffer, к этому моменту буфер всегда заполнен полностью
			auto written = write_all(m_output_buffer, m_output_buffer_size);
			if (written == m_output_buffer_size)
				setp(m_output_buffer, m_output_buffer + m_output_buffer_size);
			else
			{	// написали меньше чем хотели, сдвигаем оставшиеся в начало буфера, выставляем указатели
				auto last = std::move(m_output_buffer + written, m_output_buffer + m_output_buffer_size, m_output_buffer);
				setp(last, m_output_buffer + m_output_buffer_size);
				auto prev_data_count = m_output_buffer_size - buffer_avail;
				return written > prev_data_count ? written - buffer_avail : 0;
			}
		}

		// в буфер не поместимся - пишем прямиком в сокет все что осталось, иначе скидываем в буфер
		if (count > m_output_buffer_size)
			return written_though_buffer + write_all(ptr, count);
		else
		{
			std::copy_n(ptr, count, m_output_buffer);
			pbump(static_cast<int>(count));
			return written_though_buffer + count;
		}
	}

	auto socket_streambuf_base::overflow(int_type ch /* = traits_type::eof() */) -> int_type
	{
		auto written = write_some(m_output_buffer, m_output_buffer_size);
		if (written <= 0) return traits_type::eof();

		auto last = std::move(m_output_buffer + written, m_output_buffer + m_output_buffer_size, m_output_buffer);
		setp(last, m_output_buffer + m_output_buffer_size);
		if (!traits_type::eq_int_type(ch, traits_type::eof()))
			sputc(traits_type::to_char_type(ch));

		return traits_type::not_eof(ch);
	}

	int socket_streambuf_base::sync()
	{
		auto first = m_output_buffer;
		auto last = pptr();

		std::size_t count = last - first;
		std::size_t written = write_all(first, count);
		if (count == written)
		{
			setp(m_output_buffer, m_output_buffer + m_output_buffer_size);
			return 0;
		}
		else
		{
			setp(nullptr, nullptr);
			return -1;
		}
	}

	std::streambuf * socket_streambuf_base::setbuf(char_type * buffer, std::streamsize size)
	{
		if (size < minimum_buffer_size) throw std::logic_error("socket_streambuf_base::setbuf size should >= minimum_buffer_size");
		if (size > INT_MAX)             throw std::logic_error("socket_streambuf_base::setbuf size should <= INT_MAX");

		if (buffer == nullptr)
		{
		    reset_buffers(size);
		    return this;
		}

		if (m_own_input_buffer)  delete [] m_input_buffer;
		if (m_own_output_buffer) delete [] m_output_buffer;

		m_default_internal_buffer = false;
		m_own_input_buffer = false;
		m_own_output_buffer = false;
		
		m_input_buffer = buffer;
		m_input_buffer_size = static_cast<unsigned>(size / 2);
		m_output_buffer = m_input_buffer + m_input_buffer_size;
		m_output_buffer_size = m_input_buffer_size;

		set_buffers();
		return this;
	}

	std::streambuf * socket_streambuf_base::setbuf(bool owning, char_type * buffer, std::streamsize input_size, std::streamsize output_size)
	{
		if (input_size < minimum_buffer_size)      throw std::logic_error("socket_streambuf_base::setbuf input_size should >= minimum_buffer_size");
		if (output_size < minimum_buffer_size)     throw std::logic_error("socket_streambuf_base::setbuf output_size should >= minimum_buffer_size");
		if (input_size > INT_MAX)  throw std::logic_error("socket_streambuf_base::setbuf input_size should <= INT_MAX");
		if (output_size > INT_MAX) throw std::logic_error("socket_streambuf_base::setbuf output_size should <= INT_MAX");

		if (buffer == nullptr)
		{
		    reset_buffers(input_size + output_size);
		    return this;
		}

		if (m_own_input_buffer)  delete [] m_input_buffer;
		if (m_own_output_buffer) delete [] m_output_buffer;

		m_default_internal_buffer = false;
		m_own_input_buffer = owning;
		m_own_output_buffer = false;
		
		m_input_buffer = buffer;
		m_input_buffer_size = static_cast<unsigned>(input_size);
		m_output_buffer = m_input_buffer + m_input_buffer_size;
		m_output_buffer_size = static_cast<unsigned>(output_size);

		set_buffers();
		return this;
	}

	std::streambuf * socket_streambuf_base::setbuf(bool input_owning, char_type * input_buffer, std::streamsize input_size,
	                                               bool output_owning, char_type * output_buffer, std::streamsize output_size)
	{
		if (not input_buffer)      throw std::logic_error("socket_streambuf_base::setbuf input_buffer must not be bull");
		if (not output_buffer)     throw std::logic_error("socket_streambuf_base::setbuf output_buffer must not be bull");

		if (input_size < minimum_buffer_size)      throw std::logic_error("socket_streambuf_base::setbuf input_size should >= minimum_buffer_size");
		if (output_size < minimum_buffer_size)     throw std::logic_error("socket_streambuf_base::setbuf output_size should >= minimum_buffer_size");
		if (input_size > INT_MAX)  throw std::logic_error("socket_streambuf_base::setbuf input_size should <= INT_MAX");
		if (output_size > INT_MAX) throw std::logic_error("socket_streambuf_base::setbuf output_size should <= INT_MAX");

		if (m_own_input_buffer)  delete [] m_input_buffer;
		if (m_own_output_buffer) delete [] m_output_buffer;

		m_default_internal_buffer = false;
		m_own_input_buffer = input_owning;
		m_own_output_buffer = output_owning;
		
		m_input_buffer = input_buffer;
		m_input_buffer_size = static_cast<unsigned>(input_size);
		m_output_buffer = output_buffer;
		m_output_buffer_size = static_cast<unsigned>(output_size);

		set_buffers();
		return this;
	}

	/************************************************************************/
	/*              ctors/dtors                                             */
	/************************************************************************/
	socket_streambuf_base::~socket_streambuf_base()
	{
		if (m_own_input_buffer)  delete [] m_input_buffer;
		if (m_own_output_buffer) delete [] m_output_buffer;
	}

	socket_streambuf_base::socket_streambuf_base(socket_streambuf_base && op) noexcept
		: base_type(std::move(op)),
		  m_input_buffer(std::exchange(op.m_input_buffer, nullptr)),
		  m_output_buffer(std::exchange(op.m_output_buffer, nullptr)),
		  m_input_buffer_size(std::move(op.m_input_buffer_size)),
		  m_output_buffer_size(std::move(op.m_output_buffer_size)),
		  m_tie_io(std::exchange(op.m_tie_io, true)),
		  m_default_internal_buffer(std::exchange(op.m_default_internal_buffer, false)),
		  m_own_input_buffer(std::exchange(op.m_own_input_buffer, false)),
		  m_own_output_buffer(std::exchange(op.m_own_output_buffer, false))
	{}

	socket_streambuf_base & socket_streambuf_base::operator =(socket_streambuf_base && op) noexcept
	{
		if (this != &op)
		{
			base_type::operator =(std::move(op));
			m_input_buffer = std::exchange(op.m_input_buffer, nullptr);
			m_output_buffer = std::exchange(op.m_output_buffer, nullptr);
			m_input_buffer_size = std::move(op.m_input_buffer_size);
			m_output_buffer_size = std::move(op.m_output_buffer_size);
			m_tie_io = std::move(op.m_tie_io);
			m_default_internal_buffer = std::exchange(op.m_default_internal_buffer, false);
			m_own_input_buffer = std::exchange(op.m_own_input_buffer, false);
			m_own_output_buffer = std::exchange(op.m_own_output_buffer, false);
		}

		return *this;
	}

	void socket_streambuf_base::swap(socket_streambuf_base & op) noexcept
	{
		using std::swap;
		base_type::swap(op);
		swap(m_input_buffer, op.m_input_buffer);
		swap(m_output_buffer, op.m_output_buffer);
		swap(m_input_buffer_size, op.m_input_buffer_size);
		swap(m_output_buffer_size, op.m_output_buffer_size);
		swap(m_tie_io, op.m_tie_io);
		swap(m_own_input_buffer, op.m_own_input_buffer);
	}
}
