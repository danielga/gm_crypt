newoption({
	trigger = "compile-cryptopp",
	description = "Compile cryptopp along with the modules"
})

GARRYSMOD_MODULE_BASE_FOLDER = "../gmod-module-base"
SCANNING_FOLDER = "../scanning"
SOURCE_FOLDER = "../Source"
CRYPTOPP_FOLDER = "../cryptopp"
PROJECT_FOLDER = os.get() .. "/" .. _ACTION

solution("gm_crypt")
	language("C++")
	location(PROJECT_FOLDER)
	flags({"NoPCH", "StaticRuntime"})
	platforms({"x86"})
	configurations({"Release", "Debug"})

	filter("platforms:x86")
		architecture("x32")

	filter("configurations:Release")
		optimize("On")
		vectorextensions("SSE2")
		objdir(PROJECT_FOLDER .. "/Intermediate")
		targetdir(PROJECT_FOLDER .. "/Release")

	filter("configurations:Debug")
		flags({"Symbols"})
		objdir(PROJECT_FOLDER .. "/Intermediate")
		targetdir(PROJECT_FOLDER .. "/Debug")

	project("gmsv_crypt")
		kind("SharedLib")
		defines({"GMMODULE", "CRYPT_SERVER"})
		includedirs({
			SOURCE_FOLDER,
			GARRYSMOD_MODULE_BASE_FOLDER .. "/include"
			SCANNING_FOLDER
		})
		files({
			SOURCE_FOLDER .. "/*.cpp",
			SOURCE_FOLDER .. "/*.hpp",
			SCANNING_FOLDER .. "/SymbolFinder.cpp"
		})
		vpaths({
			["Header files"] = SOURCE_FOLDER .. "/**.hpp",
			["Source files"] = {
				SOURCE_FOLDER .. "/**.cpp",
				SCANNING_FOLDER .. "/**.cpp"
			}
		})

		filter({"options:not compile-cryptopp", "system:windows"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			libdirs({CRYPTOPP_FOLDER .. "/lib"})
			links({"cryptopp"})

		filter({"options:not compile-cryptopp", "system:not windows"})
			linkoptions({"-Wl,-Bstatic,-lcryptopp,-Bdynamic"})

		filter({"options:compile-cryptopp"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			links({"cryptopp"})

		targetprefix("")
		targetextension(".dll")

		filter("system:windows")
			targetsuffix("_win32")

		filter("system:linux")
			targetsuffix("_linux")

		filter({"system:macosx"})
			targetsuffix("_mac")

	project("gmcl_crypt")
		kind("SharedLib")
		defines({"GMMODULE", "CRYPT_CLIENT"})
		includedirs({
			SOURCE_FOLDER,
			GARRYSMOD_MODULE_BASE_FOLDER .. "/include"
			SCANNING_FOLDER
		})
		files({
			SOURCE_FOLDER .. "/*.cpp",
			SOURCE_FOLDER .. "/*.hpp",
			SCANNING_FOLDER .. "/SymbolFinder.cpp"
		})
		vpaths({
			["Header files"] = SOURCE_FOLDER .. "/**.hpp",
			["Source files"] = {
				SOURCE_FOLDER .. "/**.cpp",
				SCANNING_FOLDER .. "/**.cpp"
			}
		})

		filter({"options:not compile-cryptopp", "system:windows"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			libdirs({CRYPTOPP_FOLDER .. "/lib"})
			links({"cryptopp"})

		filter({"options:not compile-cryptopp", "system:not windows"})
			linkoptions({"-Wl,-Bstatic,-lcryptopp,-Bdynamic"})

		filter({"options:compile-cryptopp"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			links({"cryptopp"})

		targetprefix("")
		targetextension(".dll")

		filter("system:windows")
			targetsuffix("_win32")

		filter("system:linux")
			targetsuffix("_linux")

		filter({"system:macosx"})
			targetsuffix("_mac")

	if _OPTIONS["compile-cryptopp"] then
		project("cryptopp")
			kind("StaticLib")
			defines({"USE_PRECOMPILED_HEADERS"})
			includedirs({
				CRYPTOPP_FOLDER .. "/include/cryptopp",
				CRYPTOPP_FOLDER .. "/src"
			})
			files({
				CRYPTOPP_FOLDER .. "/include/cryptopp/*.h",
				CRYPTOPP_FOLDER .. "/src/*.cpp"
			})
			vpaths({
				["Header files"] = CRYPTOPP_FOLDER .. "/**.h",
				["Source files"] = CRYPTOPP_FOLDER .. "/**.cpp"
			})
	end