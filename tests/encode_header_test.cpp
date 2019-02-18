#include <ext/net/mime/bencode_header.hpp>
#include <ext/net/mime/qencode_header.hpp>
#include <ext/net/mime/encode_header_parameter.hpp>

#include <boost/test/unit_test.hpp>

namespace mime = ext::net::mime;
using mime::MailDefaultLineSize;

BOOST_AUTO_TEST_CASE(bencode_header_folded_test)
{
	std::string subj = "Я очень длинный текст темы сообщения, я создан для проверки того что simple_mail header_base64_encoder правильно нарезает текст, не превышая 80 символов(включая \\r\\n)";
	std::string expected_output =
		"Subject: =?utf-8?b?0K8g0L7Rh9C10L3RjCDQtNC70LjQvdC90YvQuSDRgtC10LrRgdGCINGC?=\r\n"
		" =?utf-8?b?0LXQvNGLINGB0L7QvtCx0YnQtdC90LjRjywg0Y8g0YHQvtC30LTQsNC9INC00Ls=?=\r\n"
		" =?utf-8?b?0Y8g0L/RgNC+0LLQtdGA0LrQuCDRgtC+0LPQviDRh9GC0L4gc2ltcGxlX21haWwg?=\r\n"
		" =?utf-8?b?aGVhZGVyX2Jhc2U2NF9lbmNvZGVyINC/0YDQsNCy0LjQu9GM0L3QviDQvdCw0YA=?=\r\n"
		" =?utf-8?b?0LXQt9Cw0LXRgiDRgtC10LrRgdGCLCDQvdC1INC/0YDQtdCy0YvRiNCw0Y8gODAg?=\r\n"
		" =?utf-8?b?0YHQuNC80LLQvtC70L7QsijQstC60LvRjtGH0LDRjyBcclxuKQ==?=";

	std::string output;
	mime::bencode_header_folded(output, MailDefaultLineSize, "Subject", subj);

	BOOST_CHECK_EQUAL(output, expected_output);
}

BOOST_AUTO_TEST_CASE(bencode_header_test)
{
	std::string subj = "Я текст темы сообщения";
	std::string expected_output = "Subject: =?utf-8?b?0K8g0YLQtdC60YHRgiDRgtC10LzRiyDRgdC+0L7QsdGJ0LXQvdC40Y8=?=";

	std::string output = "Subject: ";
	mime::bencode_header(output, subj.begin(), subj.end());

	BOOST_CHECK_EQUAL(output, expected_output);
}

BOOST_AUTO_TEST_CASE(qencode_header_folded_test)
{
	std::string input = "I am a very long header text with a little я рус texт, so we can test a encode_qencoding_header can split properly на 80 borders";
	std::string expected_output =
		"Subject: =?utf-8?q?I_am_a_very_long_header_text_with_a_little_=D1=8F_=D1=80?=\r\n"
		" =?utf-8?q?=D1=83=D1=81_tex=D1=82,_so_we_can_test_a_encode_qencoding_header_?=\r\n"
		" =?utf-8?q?can_split_properly_=D0=BD=D0=B0_80_borders?=";
	
	std::string output;
	mime::qencode_header_folded(output, MailDefaultLineSize, "Subject", input);

	BOOST_CHECK_EQUAL(output, expected_output);
}

BOOST_AUTO_TEST_CASE(qencode_header_test)
{
	std::string input = "I am header with some рус text and some ?_- not allowed chars";
	std::string expected_output = "=?utf-8?q?I_am_header_with_some_=D1=80=D1=83=D1=81_text_and_some_=3F_-_not_allowed_chars?=";

	std::string output;
	mime::qencode_header(output, input.begin(), input.end());

	BOOST_CHECK_EQUAL(output, expected_output);
}

BOOST_AUTO_TEST_CASE(encode_header_parameter_folded_simple_test)
{
	std::string expected_output = "name=val; filename=\"test ola.txt\"";
	std::string output;

	std::size_t curpos = 0;
	curpos = mime::encode_header_parameter_folded(output, curpos, MailDefaultLineSize, "name", "val");
	output += "; ";
	curpos += 2;

	curpos = mime::encode_header_parameter_folded(output, curpos, MailDefaultLineSize, "filename", "test ola.txt");

	BOOST_CHECK_EQUAL(output, expected_output);
}

BOOST_AUTO_TEST_CASE(encode_header_parameter_fold_test)
{
	std::string expected_output =
		" filename*0*=utf-8''%D0%9E%D1%82%D1%87%D0%B5%D1%82%20%D0%BE%D0%B1%20%D0%BE;\r\n"
		" filename*1*=%D1%88%D0%B8%D0%B1%D0%BA%D0%B0%D1%85%20M1111111118-.pdf";

	std::string output = " ";
	mime::encode_header_parameter_folded(output, output.size(), MailDefaultLineSize, "filename", "Отчет об ошибках M1111111118-.pdf");

	BOOST_CHECK_EQUAL(output, expected_output);
}

BOOST_AUTO_TEST_CASE(encode_header_parameter_test)
{
	std::string expected_output = "filename*=utf-8''%D0%9E%D1%82%D1%87%D0%B5%D1%82%20%D0%BE%D0%B1%20%D0%BE%D1%88%D0%B8%D0%B1%D0%BA%D0%B0%D1%85%20M1111111118-.pdf";
	std::string output;
	mime::encode_header_parameter(output, "filename", "Отчет об ошибках M1111111118-.pdf");

	BOOST_CHECK_EQUAL(output, expected_output);
}
