import qbs
import qbs.Environment
import dmlys.BuildUtils

CppApplication
{
	type: base.concat("autotest")
	consoleApplication: true

	Depends { name: "cpp" }
	Depends { name: "extlib" }
	Depends { name: "netlib" }
	Depends { name: "dmlys.qbs-common"; required: false }
	Depends { name: "ProjectSettings"; required: false }

	cpp.cxxLanguageVersion : "c++17"
	// on msvc boost are usually static, on posix - shared
	cpp.defines: qbs.toolchain.contains("msvc") ? [] : ["BOOST_TEST_DYN_LINK"]

	cpp.dynamicLibraries:
	{
		if (qbs.toolchain.contains("gcc") || qbs.toolchain.contains("clang"))
		{
			var libs = ["stdc++fs", "fmt",
				//"boost_system",
				"boost_program_options",
				//"boost_test_exec_monitor",
				"boost_unit_test_framework",
			]
			
			if (extlib.with_zlib)
				libs.push("z")
			
			if (extlib.with_openssl)
				libs = libs.concat(["ssl", "crypto"])
			
			if (qbs.toolchain.contains("mingw"))
				libs = libs.concat(["ws2_32", "crypt32", "ssp"]) // ssp is for mingw(gcc) stack protector, _FORTIFY_SOURCE stuff
			
			return libs
		}

		if (qbs.toolchain.contains("msvc"))
		{
			var libs = [
				"libfmt",
				// on msvc boost is autolinked
				//"boost_system",
				//"boost_program_options",
				//"boost_test_exec_monitor",
				//"boost_unit_test_framework",
			]
			
			if (extlib.with_zlib)
				libs.push("zlib")
			
			if (extlib.with_openssl)
				libs = libs.concat(["openssl-crypto", "openssl-ssl"])
			
			libs = BuildUtils.make_winlibs(qbs, cpp, libs)
			libs = libs.concat(["crypt32", "user32", "advapi32"])
			return libs
		}
		
	}

	files: [
		"tests/**",
	]
}
