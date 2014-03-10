GARRYSMOD_INCLUDES_PATH = "../gmod-module-base/include"
PROJECT_FOLDER = os.get() .. "/" .. _ACTION
SOURCE_FOLDER = "../Source/"

solution("gm_crypt")
	language("C++")
	location(PROJECT_FOLDER)

	if os.is("macosx") then
		platforms({"Universal32"})
	else
		platforms({"x32"})
	end
--[[
	configuration("windows")
		includedirs({os.get() .. "/cryptopp/include"})
		links({"cryptopp"})

		configuration({"windows", "Debug"})
			libdirs({os.get() .. "/cryptopp/lib/debug"})

		configuration({"windows", "Release"})
			libdirs({os.get() .. "/cryptopp/lib/release"})

	configuration("not windows")
		linkoptions({"-Wl,-Bstatic,-lcryptopp,-Bdynamic"})
]]
	configurations({"Debug", "Release"})

	configuration("Debug")
		defines({"DEBUG"})
		flags({"Symbols"})
		targetdir(PROJECT_FOLDER .. "/Debug")
		objdir(PROJECT_FOLDER .. "/Intermediate")

	configuration("Release")
		defines({"NDEBUG"})
		flags({"Optimize", "EnableSSE"})
		targetdir(PROJECT_FOLDER .. "/Release")
		objdir(PROJECT_FOLDER .. "/Intermediate")

	project("gmsv_crypt")
		kind("SharedLib")
		flags({"NoPCH", "ExtraWarnings"})
		defines({"CRYPT_SERVER", "GMMODULE"})
		includedirs({SOURCE_FOLDER, GARRYSMOD_INCLUDES_PATH, "windows/cryptopp/include"})
		files({SOURCE_FOLDER .. "*.hpp", SOURCE_FOLDER .. "*.cpp"})
		vpaths({["Header files"] = "**.hpp", ["Source files"] = "**.cpp"})
		links({"cryptopp"})
		
		targetprefix("gmsv_") -- Just to remove prefixes like lib from Linux
		targetname("crypt")

		configuration("windows")
			targetsuffix("_win32")

		configuration("linux")
			targetsuffix("_linux")
			targetextension(".dll") -- Derp Garry, WHY

		configuration("macosx")
			targetsuffix("_mac")
			targetextension(".dll") -- Derp Garry, WHY

	project("gmcl_crypt")
		kind("SharedLib")
		flags({"NoPCH", "ExtraWarnings"})
		defines({"CRYPT_CLIENT", "GMMODULE"})
		includedirs({SOURCE_FOLDER, GARRYSMOD_INCLUDES_PATH, "windows/cryptopp/include"})
		files({SOURCE_FOLDER .. "*.hpp", SOURCE_FOLDER .. "*.cpp"})
		vpaths({["Header files"] = "**.hpp", ["Source files"] = "**.cpp"})
		links({"cryptopp"})

		targetprefix("gmcl_") -- Just to remove prefixes like lib from Linux
		targetname("crypt")

		configuration("windows")
			targetsuffix("_win32")

		configuration("linux")
			targetsuffix("_linux")
			targetextension(".dll") -- Derp Garry, WHY

		configuration("macosx")
			targetsuffix("_mac")
			targetextension(".dll") -- Derp Garry, WHY

	project("cryptopp")
		kind("StaticLib")
		defines({"USE_PRECOMPILED_HEADERS"})
		includedirs({"windows/cryptopp/include/cryptopp", "windows/cryptopp/src"})
		files({"windows/cryptopp/include/cryptopp/*.h", "windows/cryptopp/src/*.cpp"})
		vpaths({["Header files"] = {"**.h"}, ["Source files"] = {"**.cpp"}})