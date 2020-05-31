#define BOOST_TEST_MODULE "netlib tests"
//#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "test_files.h"

#include <ext/net/socket_base.hpp>
#include <ext/future.hpp>

struct GlobalFixture
{
	GlobalFixture()
	{
		ext::init_future_library();
		ext::net::socket_stream_init();
		
		auto argc = boost::unit_test::framework::master_test_suite().argc;
		auto argv = boost::unit_test::framework::master_test_suite().argv;

		if (argc >= 2)
		{
			std::filesystem::path files_location = argv[1];
			std::error_code ec;
			if (std::filesystem::exists(files_location, ec))
			{
				test_files_location = files_location;
			}
		}
	}
	
	~GlobalFixture()
	{
		ext::net::socket_stream_cleanup();
		ext::free_future_library();
	}
};

BOOST_GLOBAL_FIXTURE(GlobalFixture);
