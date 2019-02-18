#define BOOST_TEST_MODULE "net test"
//#define BOOST_TEST_MAIN
#include <boost/test/unit_test.hpp>
#include "test_files.h"

struct GlobalFixture
{
	GlobalFixture()
	{
		auto argc = boost::unit_test::framework::master_test_suite().argc;
		auto argv = boost::unit_test::framework::master_test_suite().argv;

		if (argc >= 2)
		{
			boost::filesystem::path files_location = argv[1];
			boost::system::error_code ec;
			if (boost::filesystem::exists(files_location, ec))
			{
				test_files_location = files_location;
			}
		}
	}
};

BOOST_GLOBAL_FIXTURE(GlobalFixture);
