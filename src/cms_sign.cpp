#ifdef EXT_ENABLE_OPENSSL
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/cms.h>

#include <ext/net/mail/cms_sign.hpp>

namespace ext::net::mail
{
	namespace 
	{
		struct cms_contentinfo_deleter { void operator()(CMS_ContentInfo * info) { CMS_ContentInfo_free(info); } };
		using cms_contentinfo_ptr = std::unique_ptr<CMS_ContentInfo, cms_contentinfo_deleter>;	
	}
	
	std::string sign_email(EVP_PKEY * pkey, X509 * x509, stack_st_X509 * additional_certs, std::string_view msg_body, bool detached)
	{
		using namespace ext::openssl;
		
		bio_uptr bio_input_ptr, bio_output_ptr;
		bio_input_ptr.reset( ::BIO_new_mem_buf(msg_body.data(), static_cast<int>(msg_body.size())) );
		bio_output_ptr.reset( ::BIO_new(::BIO_s_mem()) );

		if (not bio_input_ptr)  throw_last_error("ext::net::openssl::sign_mail: input  BIO_mem fail(::BIO_new_mem_buf)");
		if (not bio_output_ptr) throw_last_error("ext::net::openssl::sign_mail: output BIO_mem fail(::BIO_new(::BIO_s_mem()))");

		int flags = CMS_CRLFEOL;
		if (detached) flags |= CMS_DETACHED;

		cms_contentinfo_ptr cms_info(::CMS_sign(x509, pkey, additional_certs, bio_input_ptr.get(), flags));
		if (not cms_info) throw_last_error("ext::net::openssl::sign_mail: CMS_sign call failure");

		int res = ::SMIME_write_CMS(bio_output_ptr.get(), cms_info.get(), bio_input_ptr.get(), flags);
		if (res <= 0) throw_last_error("ext::net::openssl::sign_mail: SMIME_write_CMS call failure");

		char * data;
		int len = BIO_get_mem_data(bio_output_ptr.get(), &data);
		return std::string(data, len);
	}	
}


#endif
