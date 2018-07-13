#pragma once
#include <ctime>
#include <chrono>
#include <algorithm>

#include <ext/is_string.hpp>
#include <ext/range/as_literal.hpp>
#include <ext/time_fmt.hpp>

#include <ext/netlib/mime/encode_header.hpp>
#include <ext/netlib/mime/encode_header_parameter.hpp>

namespace ext::netlib::mail
{
	template <class NameString, class ValueString>
	struct unstructured_header_holder
	{
		using name_string = NameString;
		using value_string = ValueString;

		name_string  name;
		value_string value;

	public:
		unstructured_header_holder(name_string name, value_string value)
			: name(std::move(name)), value(std::move(value)) {}
	};


	template <class NameString, class ValueString>
	auto unstructured_header(const NameString & name, const ValueString & value)
	{
		static_assert(ext::is_string_v<NameString>);
		static_assert(ext::is_string_v<ValueString>);

		auto name_lit  = ext::as_literal(name);
		auto value_lit = ext::as_literal(value);

		return unstructured_header_holder(name_lit, value_lit);
	}


	template <class NameString, class ValueStrings>
	struct address_header_holder
	{
		using name_string   = NameString;
		using value_strings = ValueStrings;

		name_string   name;
		value_strings values;

	public:
		address_header_holder(name_string name, value_strings values)
			: name(std::move(name)), values(std::move(values)) {}
	};

	
	template <class NameString, class ValueStrings>
	auto address_header(const NameString & name, const ValueStrings & values)
	{
		static_assert(ext::is_string_v<NameString>);
		static_assert(ext::is_string_or_string_range_v<ValueStrings>);

		auto name_lit   = ext::as_literal(name);
		auto values_lit = ext::as_literal(values);

		return address_header_holder(name_lit, values_lit);
	}


	template <class NameString>
	struct date_header_holder
	{
		using name_string = NameString;

		name_string name;
		std::time_t time;

	public:
		date_header_holder(name_string name, std::time_t time)
			: name(std::move(name)), time(std::move(time)) {}
	};

	template <class NameString>
	auto date_header(const NameString & name, std::time_t time)
	{
		static_assert(ext::is_string_v<NameString>);

		auto name_lit = ext::as_literal(name);
		return date_header_holder(name_lit, time);
	}

	template <class NameString>
	inline auto date_header(const NameString & name, std::chrono::system_clock::time_point point)
	{
		return date_header(name, std::chrono::system_clock::to_time_t(point));
	}


	template <class Destination, class ... Types>
	Destination & print_header(Destination & dest, const unstructured_header_holder<Types...> & header)
	{
		mime::encode_header_folded(dest, mime::MailDefaultLineSize, header.name, header.value);
		write_string(dest, "\r\n");
		return dest;
	}

	template <class Destination, class ... Types>
	Destination & print_header(Destination & dest, const date_header_holder<Types...> & header)
	{
		auto timezone = ext::as_literal(" +0000");
		// 30 May 2015 23:15:00 +0000
		constexpr unsigned buffer_size = 64;
		char buffer[buffer_size];

		std::tm struct_tm;
		ext::gmtime(&header.time, &struct_tm);
		auto printed = std::strftime(buffer, buffer_size, "%d %b %Y %H:%M:%S", &struct_tm);
		auto last = std::copy(std::begin(timezone), std::end(timezone), buffer + printed);
		*last++ = '\r';
		*last++ = '\n';

		write_string(dest, header.name);
		write_string(dest, ": ");
		write_string(dest, buffer, last - buffer);

		return dest;
	}

	template <class Destination, class ... Types>
	Destination & print_header(Destination & dest, const address_header_holder<Types...> & header)
	{
		using header_type   = address_header_holder<Types...>;
		using name_string   = typename header_type::name_string;
		using value_strings = typename header_type::value_strings;

		if constexpr(ext::is_string_v<value_strings>)
		{
			write_string(dest, header.name);
			write_string(dest, ": ");
			write_string(dest, header.values);
			write_string(dest, "\r\n");
		}
		else
		{
			auto first = boost::begin(header.values);
			auto last  = boost::end(header.values);

			if (first != last)
			{
				auto ident = boost::size(header.name) + 2;
				std::string sepr = ",\r\n";
				sepr.append(ident, ' ');

				write_string(dest, header.name);
				write_string(dest, ": ");

				write_string(dest, *first);
				for (++first; first != last; ++first)
				{
					write_string(dest, sepr);
					write_string(dest, *first);
				}

				write_string(dest, "\r\n");
			}
		}

		return dest;
	}

	template <class Destination, class ... Types>
	inline Destination & operator <<(Destination & dest, const unstructured_header_holder<Types...> & header)
	{
		return print_header(dest, header);
	}

	template <class Destination, class ... Types>
	inline Destination & operator <<(Destination & dest, const address_header_holder<Types...> & header)
	{
		return print_header(dest, header);
	}

	template <class Destination, class ... Types>
	inline Destination & operator <<(Destination & dest, const date_header_holder<Types...> & header)
	{
		return print_header(dest, header);
	}
}
