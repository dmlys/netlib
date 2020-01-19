#include <string>
#include <string_view>
#include <algorithm>

#include <ext/net/http/parse_header.hpp>

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
		par_str = std::string_view(first, last - first);

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
}
