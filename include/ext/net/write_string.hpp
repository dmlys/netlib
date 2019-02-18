#pragma once
#include <ext/is_string.hpp>   // for ext::is_string
#include <ext/type_traits.hpp> // for ext::is_iterator
#include <ext/range.hpp>       // for ext::is_range
#include <ext/iostreams/utility.hpp>


namespace ext::net
{
	/// generic write_string functions, can write into:
	/// * iterators
	/// * containers
	/// * iostreams/boost::iostreams devices
	/// returns how much have been written
	
	/// size of temporary utility buffer, created on stack, used by some write_string methods
	constexpr std::size_t tmp_buffer_size = 256;

	template <class OutputIterator, class String>
	std::enable_if_t<ext::is_iterator_v<OutputIterator>, std::size_t>
	write_string(OutputIterator & out, const String & str)
	{
		auto str_lit = ext::str_view(str);
		out = std::copy(begin(str_lit), end(str_lit), out);
		return str_lit.size();
	}

	template <class OutputContainer, class String>
	std::enable_if_t<ext::is_container_v<OutputContainer>, std::size_t>
	write_string(OutputContainer & out, const String & str)
	{
		using std::begin; using std::end;
		auto str_lit = ext::str_view(str);
		ext::append(out, begin(str_lit), end(str_lit));
		return str_lit.size();
	}

	template <class Sink, class String>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
	write_string(Sink & sink, const String & str)
	{
		auto str_lit = ext::str_view(str);
		ext::iostreams::write_string(sink, str_lit);
		return str_lit.size();
	}


	template <class OutputIterator, class Iterator>
	std::enable_if_t<ext::is_iterator_v<OutputIterator>, std::size_t>
	write_string(OutputIterator & out, Iterator first, Iterator last)
	{
		out = std::copy(first, last, out);
		return last - first;
	}

	template <class OutputContainer, class Iterator>
	std::enable_if_t<ext::is_container_v<OutputContainer>, std::size_t>
	write_string(OutputContainer & out, Iterator first, Iterator last)
	{
		ext::append(out, first, last);
		return last - first;
	}

	template <class Sink, class Iterator>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
	write_string(Sink & sink, Iterator first, Iterator last)
	{
		using char_type = typename std::iterator_traits<Iterator>::value_type;
		constexpr auto buffer_size = tmp_buffer_size;
		char_type buffer[buffer_size];
		std::size_t written = 0;

		do
		{
			auto step_size = std::min<std::size_t>(last - first, buffer_size);
			auto stop = first + step_size;
			std::copy(first, stop, buffer);

			ext::iostreams::write_all(sink, buffer, step_size);
			written += step_size;
			first = stop;

		} while (first < last);

		return written;
	}

	template <class Sink, class CharType>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
	write_string(Sink & sink, const CharType * first, const CharType * last)
	{
		ext::iostreams::write_all(sink, first, last - first);
		return last - first;
	}
	
	
	template <class OutputIterator, class CharType>
	std::enable_if_t<ext::is_iterator_v<OutputIterator>, std::size_t>
	write_string(OutputIterator & out, const CharType * str, std::size_t len)
	{
		out = std::copy(str, str + len, out);
		return len;
	}

	template <class OutputContainer, class CharType>
	std::enable_if_t<ext::is_container_v<OutputContainer>, std::size_t>
	write_string(OutputContainer & out, const CharType * str, std::size_t len)
	{
		ext::append(out, str, str + len);
		return len;
	}

	template <class Sink, class CharType>
	std::enable_if_t<ext::iostreams::is_device_v<Sink>, std::size_t>
	write_string(Sink & sink, const CharType * str, std::size_t len)
	{
		ext::iostreams::write_all(sink, str, len);
		return len;
	}
}
