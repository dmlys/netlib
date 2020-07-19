#include <string>
#include <string_view>
#include <clocale>
#include <sstream>
#include <locale>
#include <algorithm>

#include <ext/net/http/parse_header.hpp>
#include <boost/predef.h>


namespace ext::net::http
{
	static std::string & trim(std::string & view)
	{
		auto first = view.data();
		auto last  = first + view.size();
		auto notspace = [](char ch) { return ch != ' '; };

		// trim left
		first = std::find_if(first, last, notspace);
		// trim right
		last = std::find_if(std::make_reverse_iterator(last), std::make_reverse_iterator(first), notspace).base();

		return view.assign(first, last);
	}

	static std::string_view & trim(std::string_view & view) noexcept
	{
		auto first = view.data();
		auto last  = first + view.size();
		auto notspace = [](char ch) { return ch != ' '; };

		// trim left
		first = std::find_if(first, last, notspace);
		// trim right
		last = std::find_if(std::make_reverse_iterator(last), std::make_reverse_iterator(first), notspace).base();

		return view = std::string_view(first, last - first);
	}


	bool parse_header_value(std::string & header_str, std::string & value, std::string & params)
	{
		auto first = header_str.data();
		auto last  = first + header_str.size();
		if (first == last) return false;

		last = std::find(first, last, ',');
		auto vallast = std::find(first, last, ';');
		auto parfirst = vallast;
		if (parfirst != last) ++parfirst;

		value.assign(first, vallast);
		params.assign(parfirst, last);

		trim(value);
		trim(params);

		first = last;
		last = header_str.data() + header_str.size();
		if (first != last) ++first;
		header_str.assign(first, last);

		return true;
	}

	bool parse_header_value(std::string_view & header_str, std::string_view & value, std::string_view & params) noexcept
	{
		auto first = header_str.data();
		auto last  = first + header_str.size();
		if (first == last) return false;

		last = std::find(first, last, ',');
		auto vallast = std::find(first, last, ';');
		auto parfirst = vallast;
		if (parfirst != last) ++parfirst;

		value  = std::string_view(first, vallast - first);
		params = std::string_view(parfirst, last - parfirst);

		trim(value);
		trim(params);

		first = last;
		last = header_str.data() + header_str.size();
		if (first != last) ++first;
		header_str = std::string_view(first, last - first);

		return true;
	}

	bool extract_header_value(std::string_view header_str, std::string_view value, std::string & params)
	{
		std::string_view curvalue, curparams;
		while (parse_header_value(header_str, curvalue, curparams))
			if (curvalue == value)
			{
				params.assign(curparams.begin(), curparams.end());
				return true;
			}

		return false;
	}

	bool extract_header_value(std::string_view header_str, std::string_view value, std::string_view & params) noexcept
	{
		std::string_view curvalue, curparams;
		while (parse_header_value(header_str, curvalue, curparams))
			if (curvalue == value)
			{
				params = curparams;
				return true;
			}

		return false;
	}

	bool parse_header_parameter(std::string & par_str, std::string & name, std::string & value)
	{
		auto first = par_str.data();
		auto last  = first + par_str.size();
		if (first == last) return false;

		last = std::find(first, last, ';');
		auto namelast = std::find(first, last, '=');
		auto valfirst = namelast;
		if (valfirst != last) ++valfirst;

		name.assign(first, namelast);
		value.assign(valfirst, last);

		trim(name);
		trim(value);

		first = last;
		last = par_str.data() + par_str.size();
		if (first != last) ++first;
		par_str.assign(first, last);

		return true;
	}

	bool parse_header_parameter(std::string_view & par_str, std::string_view & name, std::string_view & value) noexcept
	{
		auto first = par_str.data();
		auto last  = first + par_str.size();
		if (first == last) return false;

		last = std::find(first, last, ';');
		auto namelast = std::find(first, last, '=');
		auto valfirst = namelast;
		if (valfirst != last) ++valfirst;

		name  = std::string_view(first, namelast - first);
		value = std::string_view(valfirst, last - valfirst);

		trim(name);
		trim(value);

		first = last;
		last = par_str.data() + par_str.size();
		if (first != last) ++first;
		par_str = std::string_view(first, last - first);

		return true;
	}

	bool extract_header_parameter(std::string_view par_str, std::string_view name, std::string & value)
	{
		std::string_view curname, curvalue;
		while (parse_header_parameter(par_str, curname, curvalue))
			if (curname == name)
			{
				value.assign(curvalue.begin(), curvalue.end());
				return true;
			}

		return false;
	}

	bool extract_header_parameter(std::string_view par_str, std::string_view name, std::string_view & value) noexcept
	{
		std::string_view curname, curvalue;
		while (parse_header_parameter(par_str, curname, curvalue))
			if (curname == name)
			{
				value = curvalue;
				return true;
			}

		return false;
	}

	bool parse_query(std::string & query_str, std::string & name, std::string & value)
	{
		auto first = query_str.data();
		auto last  = first + query_str.size();
		if (first == last) return false;

		last = std::find(first, last, '&');
		auto namelast = std::find(first, last, '=');
		auto valfirst = namelast;
		if (valfirst != last)
			++valfirst;
		else
		{
			namelast = first;
			valfirst = first;
		}

		name.assign(first, namelast);
		value.assign(valfirst, last);

		trim(name);
		trim(value);

		first = last;
		last = query_str.data() + query_str.size();
		if (first != last) ++first;
		query_str.assign(first, last);

		return true;
	}

	bool parse_query(std::string_view & query_str, std::string_view & name, std::string_view & value) noexcept
	{
		auto first = query_str.data();
		auto last  = first + query_str.size();
		if (first == last) return false;

		last = std::find(first, last, '&');
		auto namelast = std::find(first, last, '=');
		auto valfirst = namelast;
		if (valfirst != last)
			++valfirst;
		else
		{
			namelast = first;
			valfirst = first;
		}

		name  = std::string_view(first, namelast - first);
		value = std::string_view(valfirst, last - valfirst);

		trim(name);
		trim(value);

		first = last;
		last = query_str.data() + query_str.size();
		if (first != last) ++first;
		query_str = std::string_view(first, last - first);

		return true;
	}

	bool extract_query(std::string_view qurey_str, std::string_view name, std::string & value)
	{
		std::string_view curname, curvalue;
		while (parse_query(qurey_str, curname, curvalue))
			if (curname == name)
			{
				value.assign(curvalue.begin(), curvalue.end());
				return true;
			}

		return false;
	}

	bool extract_query(std::string_view qurey_str, std::string_view name, std::string_view & value) noexcept
	{
		std::string_view curname, curvalue;
		while (parse_query(qurey_str, curname, curvalue))
			if (curname == name)
			{
				value = curvalue;
				return true;
			}

		return false;
	}

#if BOOST_OS_WINDOWS
	static _locale_t cloc = _create_locale(LC_NUMERIC, "C");
	#define strtod_l _strtod_l
#elif BOOST_LIB_STD_GNU or BOOST_LIB_STD_CXX
	static locale_t cloc = newlocale(LC_ALL_MASK, "C", nullptr);
#endif

	double parse_weight(std::string_view str, double invval/* = 0.0*/)
	{
	#if BOOST_LIB_STD_GNU or BOOST_LIB_STD_CXX
		// on glibc at least on 2020/03/11 std::from_chars is not implemented for floating types
		// use strtod_l instead, through it's unsafe, because it's works with zero terminated strings, and we have string_view

		errno = 0;
		double result = strtod_l(str.data(), nullptr, cloc);
		if (result == 0.0 and errno) return invval;

		return result;

	#elif __cplusplus >= 201703L
		// c++ 17 have std::from_chars which parses always and only witch C locale, but fast and efficient
		auto first = str.data();
		auto last  = first + str.size();

		double val = invval;
		std::from_chars(first, last, val);
		return val;
	#else
		// fallback to slow std::istringstream with classic locale
		std::istringstream ss(std::string(str.data(), str.data() + str.size()));
		ss.imbue(std::locale::classic());

		double result = invval;
		ss >> result;

		return result;
	#endif
	}

	double extract_weight(std::string_view field, std::string_view name, double defval/* = 0.0*/)
	{
		std::string_view parstr, parval;
		if (not extract_header_value(field, name, parstr))
			return 0;

		if (extract_header_parameter(parstr, "q", parval))
			return parse_weight(parval, defval);
		else
			return defval;
	}

}
