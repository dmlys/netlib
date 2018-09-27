import qbs
import qbs.Environment

StaticLibrary
{
	Depends { name: "cpp" }
	Depends { name: "extlib" }

	cpp.cxxLanguageVersion : "c++17"

	cpp.defines: additionalDefines
	cpp.cxxFlags: project.additionalCxxFlags
	//cpp.driverFlags: project.additionalDriverFlags
	//cpp.includePaths: project.additionalIncludePaths
	cpp.libraryPaths: project.additionalLibraryPaths

	cpp.driverFlags: {
		var flags = []
		if (qbs.toolchain.contains("gcc") || qbs.toolchain.contains("clang"))
			flags.push("-pthread")

		return flags
	}

	cpp.includePaths : {
		var includes = ["include"]
		if (project.additionalIncludePaths)
			includes = includes.uniqueConcat(project.additionalIncludePaths)

		var envIncludes = Environment.getEnv("QBS_THIRDPARTY_INCLUDES")
		if (envIncludes)
		{
			envIncludes = envIncludes.split(qbs.pathListSeparator)
			includes = includes.uniqueConcat(envIncludes)
		}

		return includes
	}

	Export
	{
		Depends { name: "cpp" }

		cpp.cxxLanguageVersion : "c++17"
		cpp.includePaths : ["include"]
	}

	files: [
		"include/ext/netlib/**",
		"src/**",
	]
}
