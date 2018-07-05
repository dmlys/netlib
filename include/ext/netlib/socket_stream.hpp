#pragma once
#include <ext/iostreams/utils.hpp>
#include <ext/iostreams/socket_stream.hpp>

namespace ext {
namespace netlib
{
	typedef ext::socket_stream    socket_stream;
	typedef ext::socket_streambuf socket_streambuf;
	
	// using ext::iostreams::write_all;
	// using ext::iostreams::write_string;	
}}
