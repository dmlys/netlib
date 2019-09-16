import qbs
import qbs.Environment


CppApplication
{
	type: base.concat("autotest")

	Depends { name: "cpp" }
	Depends { name: "extlib" }
	Depends { name: "netlib" }
	Depends { name: "ProjectSettings"; required: false }

	cpp.cxxLanguageVersion : "c++17"
	cpp.cxxFlags: project.additionalCxxFlags
	cpp.driverFlags: project.additionalDriverFlags
	cpp.defines: ["BOOST_TEST_DYN_LINK"].uniqueConcat(project.additionalDefines || [])
	cpp.systemIncludePaths: project.additionalSystemIncludePaths
	cpp.includePaths: ["include"].uniqueConcat(project.additionalIncludePaths || [])
	cpp.libraryPaths: project.additionalLibraryPaths


	cpp.dynamicLibraries: [
		"stdc++fs", "fmt", "z",
		//"boost_system",
		//"boost_test_exec_monitor",
		"boost_unit_test_framework",
	]

	files: [
		"tests/**"
    ]
}
