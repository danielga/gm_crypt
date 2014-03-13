newoption({
	trigger = "compile-cryptopp",
	description = "Compile cryptopp along with the modules"
})

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

	if not _OPTIONS["compile-cryptopp"] then
		configuration("windows")
			includedirs({"windows/cryptopp/include"})
			libdirs({"windows/cryptopp/lib"})
			links({"cryptopp"})

		configuration("not windows")
			linkoptions({"-Wl,-Bstatic,-lcryptopp,-Bdynamic"})
	end

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
		includedirs({SOURCE_FOLDER, GARRYSMOD_INCLUDES_PATH, _OPTIONS["compile-cryptopp"] and "cryptopp/include"})
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
		includedirs({SOURCE_FOLDER, GARRYSMOD_INCLUDES_PATH, _OPTIONS["compile-cryptopp"] and "cryptopp/include"})
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

	if _OPTIONS["compile-cryptopp"] then
		project("cryptopp")
			kind("StaticLib")
			defines({"USE_PRECOMPILED_HEADERS"})
			includedirs({"cryptopp/include/cryptopp", "cryptopp/src"})
			files({"cryptopp/include/cryptopp/*.h", "cryptopp/src/*.cpp"})
			vpaths({["Header files"] = "**.h", ["Source files"] = "**.cpp"})
	end
