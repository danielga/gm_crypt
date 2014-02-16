GARRYSMOD_INCLUDES_PATH = "../gmod-module-base/include"
PROJECT_FOLDER = os.get() .. "/" .. _ACTION

solution("gm_crypt")
	language("C++")
	location(PROJECT_FOLDER)
	flags({"NoPCH", "ExtraWarnings"})

	if os.is("macosx") then
		platforms({"Universal32"})
	else
		platforms({"x32"})
	end

	configuration("windows")
		includedirs({os.get() .. "/cryptopp/include"})

		configuration({"windows", "Debug"})
			libdirs({os.get() .. "/cryptopp/lib/debug"})

		configuration({"windows", "Release"})
			libdirs({os.get() .. "/cryptopp/lib/release"})

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
		defines({"CRYPT_SERVER", "GMMODULE"})
		includedirs({GARRYSMOD_INCLUDES_PATH})
		files({"../Source/*.cpp"})
		vpaths({["Source files"] = "**.cpp"})
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
		defines({"CRYPT_CLIENT", "GMMODULE"})
		includedirs({GARRYSMOD_INCLUDES_PATH})
		files({"../Source/*.cpp"})
		vpaths({["Source files"] = "**.cpp"})
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