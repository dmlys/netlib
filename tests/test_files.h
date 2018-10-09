#pragma once
#include <boost/filesystem.hpp>
#include <ext/filesystem_utils.hpp>

extern boost::filesystem::path test_files_location;

template <class Container>
void LoadTestFile(boost::filesystem::path file, Container & content,
                  std::ios_base::openmode mode = std::ios_base::in)
{
	if (!file.is_absolute())
		file = boost::filesystem::absolute(file, test_files_location);

	ext::read_file(file, content, mode);
}
