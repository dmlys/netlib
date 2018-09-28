#include <algorithm>
#include <vector>
#include <string>
#include <random>
#include <functional>
#include <ext/netlib/socket_streambuf_base.hpp>

#include <boost/test/unit_test.hpp>

namespace
{
	template <class Container>
	class test_socket_streambuf : public ext::netlib::socket_streambuf_base
	{
		Container * m_cnt;
		std::size_t m_readpos = 0;

	protected:
		std::streamsize showmanyc() override { return 0; }

		std::size_t write_some(const char_type * data, std::size_t count) override
		{
			m_cnt->insert(m_cnt->end(), data, data + count);
			return count;
		}

		std::size_t read_some(char_type * data, std::size_t count) override
		{
			std::copy_n(m_cnt->begin() + m_readpos, count, data);
			m_readpos += count;
			return count;
		}

	public:
		test_socket_streambuf(Container & cnt)
			: m_cnt(&cnt)
		{

		}
	};

	std::vector<char> generate_input(std::size_t gen_size)
	{
		std::vector<char> data;
		std::mt19937 eng;
		std::uniform_int_distribution<int> distr;

		data.resize(gen_size);
		std::generate(data.begin(), data.end(), std::bind(distr, eng));

		return data;
	}

	void test_ouput()
	{
		std::vector<char> output;
		test_socket_streambuf<std::vector<char>> strbuf {output};

		const std::size_t buffer_size = 64;
		char buffer[buffer_size * 2];
		strbuf.pubsetbuf(buffer, buffer_size * 2);

		auto input = generate_input(1024);
		std::size_t pos = 0;
		auto ptr = input.data();

		strbuf.sputn(ptr + pos, buffer_size);
		pos += buffer_size;

		strbuf.sputn(ptr + pos, buffer_size);
		pos += buffer_size;
		
		strbuf.sputn(ptr + pos, 10);
		pos += 10;

		strbuf.sputn(ptr + pos, 10);
		pos += 10;

		strbuf.sputn(ptr + pos, 10);
		pos += 10;

		strbuf.sputn(ptr + pos, buffer_size);
		pos += buffer_size;

		strbuf.pubsync();

		BOOST_CHECK(std::equal(ptr, ptr + pos, output.data()));
	}

	void test_input()
	{
		auto input = generate_input(1024);
		test_socket_streambuf<std::vector<char>> strbuf {input};

		const std::size_t buffer_size = 64;
		char buffer[buffer_size * 2];
		strbuf.pubsetbuf(buffer, buffer_size * 2);
		
		std::size_t pos = 0;
		std::vector<char> output(input.size(), 0);
		auto ptr = output.data();

		strbuf.sgetn(ptr + pos, buffer_size);
		pos += buffer_size;

		strbuf.sgetn(ptr + pos, buffer_size);
		pos += buffer_size;

		strbuf.sgetn(ptr + pos, 10);
		pos += 10;

		strbuf.sgetn(ptr + pos, 10);
		pos += 10;

		strbuf.sgetn(ptr + pos, 10);
		pos += 10;

		strbuf.sgetn(ptr + pos, buffer_size);
		pos += buffer_size;

		BOOST_CHECK(std::equal(ptr, ptr + pos, input.data()));
	}
}

BOOST_AUTO_TEST_CASE(test_socket_streambuf_base)
{
	test_ouput();
	test_input();
}