#pragma once
#include <filesystem>
#include <ext/filesystem_utils.hpp>

extern std::filesystem::path test_files_location;

template <class Container>
void LoadTestFile(std::filesystem::path file, Container & content,
                  std::ios_base::openmode mode = std::ios_base::in)
{
	file = test_files_location / file;
	ext::read_file(file, content, mode);
}
