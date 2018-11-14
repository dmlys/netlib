import qbs
import qbs.Environment


Project
{
	property bool with_openssl: false

	StaticLibrary
	{
		Depends { name: "cpp" }
		Depends { name: "extlib" }

		cpp.cxxLanguageVersion : "c++17"
		cpp.cxxFlags: project.additionalCxxFlags
		cpp.driverFlags: project.additionalDriverFlags
		//cpp.defines: project.additionalDefines
		cpp.systemIncludePaths: project.additionalSystemIncludePaths
		cpp.includePaths: ["include"].concat(project.additionalIncludePaths || [])
		cpp.libraryPaths: project.additionalLibraryPaths

		cpp.defines: {
			var defines = []

			if (project.with_openssl)
				defines.push("EXT_ENABLE_OPENSSL")

			if (project.additionalDefines)
				defines = defines.uniqueConcat(project.additionalDefines)

			return defines
		}


		Export
		{
			Depends { name: "cpp" }

			cpp.cxxLanguageVersion : "c++17"
			cpp.includePaths : ["include"]
			cpp.defines: {
				var defines = []

				if (project.with_openssl)
					defines.push("EXT_ENABLE_OPENSSL")

				return defines;
			}
		}

		files: [
			"include/ext/netlib/**",
			"src/**",
		]

		excludeFiles: {
			var excludes = [];
			if (qbs.targetOS.contains("windows"))
			{
				excludes.push("include/ext/netlib/bsdsock*")
				excludes.push("src/bsdsock*")
			}
			else
			{
				excludes.push("include/ext/netlib/winsock*")
				excludes.push("src/winsock*")
			}

			return excludes
		}

	}
}
