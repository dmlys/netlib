#pragma once
#ifdef EXT_ENABLE_OPENSSL

#include <string>
#include <ext/openssl.hpp>

namespace ext::net::mail
{
	/// signs email(msg_body) with given private key, x509 certificate and with additional certificates to be included into signature
	std::string sign_email(EVP_PKEY * pkey, X509 * x509, stack_st_X509 * additional_certs, std::string_view msg_body, bool detached);
}

#endif
