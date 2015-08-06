newoption({
	trigger = "gmcommon",
	description = "Sets the path to the garrysmod_common (https://bitbucket.org/danielga/garrysmod_common) directory",
	value = "path to garrysmod_common dir"
})

newoption({
	trigger = "compile-cryptopp",
	description = "Compile cryptopp along with the modules"
})

local gmcommon = _OPTIONS.gmcommon or os.getenv("GARRYSMOD_COMMON")
if gmcommon == nil then
	error("you didn't provide a path to your garrysmod_common (https://bitbucket.org/danielga/garrysmod_common) directory")
end

include(gmcommon)

local CRYPTOPP_FOLDER = "../cryptopp"

CreateSolution("crypt")
	warnings("Off")

	CreateProject(SERVERSIDE)
		IncludeLuaShared()
		defines({"CRYPTOPP_ENABLE_NAMESPACE_WEAK=1"})

		SetFilter({FILTER_WINDOWS, "options:not compile-cryptopp"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			libdirs({CRYPTOPP_FOLDER .. "/lib"})
			links({"cryptopp"})

		SetFilter({FILTER_LINUX, FILTER_MACOSX, "options:not compile-cryptopp"})
			linkoptions({"-Wl,-Bstatic,-lcryptopp,-Bdynamic"})

		SetFilter({"options:compile-cryptopp"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			links({"cryptopp"})

	CreateProject(CLIENTSIDE)
		IncludeLuaShared()
		defines({"CRYPTOPP_ENABLE_NAMESPACE_WEAK=1"})

		SetFilter({FILTER_WINDOWS, "options:not compile-cryptopp"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			libdirs({CRYPTOPP_FOLDER .. "/lib"})
			links({"cryptopp"})

		SetFilter({FILTER_LINUX, FILTER_MACOSX, "options:not compile-cryptopp"})
			linkoptions({"-Wl,-Bstatic,-lcryptopp,-Bdynamic"})

		SetFilter({"options:compile-cryptopp"})
			includedirs({CRYPTOPP_FOLDER .. "/include"})
			links({"cryptopp"})

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
