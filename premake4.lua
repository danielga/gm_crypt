local GARRYSMOD_INCLUDES_PATH = "gmod-module-base/include"
local project_folder = "Projects/" .. os.get() .. "/" .. _ACTION

solution("gm_crypt")

	language("C++")
	location(project_folder)
	flags({"NoPCH", "ExtraWarnings"})

	if os.is("macosx") then
		platforms({"Universal32"})
	else
		platforms({"x32"})
	end

	configurations({"Debug", "Release"})

	configuration("Debug")
		defines({"DEBUG"})
		flags({"Symbols"})
		targetdir(project_folder .. "/Debug")
		objdir(project_folder .. "/Intermediate")

	configuration("Release")
		defines({"NDEBUG"})
		flags({"Optimize", "EnableSSE"})
		targetdir(project_folder .. "/Release")
		objdir(project_folder .. "/Intermediate")

	project("gmsv_crypt")
		kind("SharedLib")
		defines({"CRYPT_SERVER", "GMMODULE"})
		includedirs({"Source", GARRYSMOD_INCLUDES_PATH})
		files({"Source/*.cpp", "Source/*.hpp"})
		vpaths({["Header files"] = {"Source/**.hpp"}, ["Source files"] = {"Source/**.cpp"}})
		links({"cryptopp"})
		
		targetprefix("gmsv_") -- Just to remove prefixes like lib from Linux
		targetname("crypt")

		configuration("windows")
			includedirs({"ThirdParty/include"})
			targetsuffix("_win32")

			configuration({"windows", "Debug"})
				libdirs({"ThirdParty/lib/debug"})

			configuration({"windows", "Release"})
				libdirs({"ThirdParty/lib/release"})

		configuration("linux")
			targetsuffix("_linux")
			targetextension(".dll") -- Derp Garry, WHY

		configuration("macosx")
			targetsuffix("_mac")
			targetextension(".dll") -- Derp Garry, WHY

	project("gmcl_crypt")
		kind("SharedLib")
		defines({"CRYPT_CLIENT", "GMMODULE"})
		includedirs({"Source", GARRYSMOD_INCLUDES_PATH})
		files({"Source/*.cpp", "Source/*.hpp"})
		vpaths({["Header files"] = {"Source/**.hpp"}, ["Source files"] = {"Source/**.cpp"}})
		links({"cryptopp"})

		targetprefix("gmcl_") -- Just to remove prefixes like lib from Linux
		targetname("crypt")

		configuration("windows")
			includedirs({"ThirdParty/include"})
			targetsuffix("_win32")

			configuration({"windows", "Debug"})
				libdirs({"ThirdParty/lib/debug"})

			configuration({"windows", "Release"})
				libdirs({"ThirdParty/lib/release"})

		configuration("linux")
			targetsuffix("_linux")
			targetextension(".dll") -- Derp Garry, WHY

		configuration("macosx")
			targetsuffix("_mac")
			targetextension(".dll") -- Derp Garry, WHY