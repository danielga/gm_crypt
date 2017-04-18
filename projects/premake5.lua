newoption({
	trigger = "compile-cryptopp",
	description = "Compile cryptopp along with the modules"
})

newoption({
	trigger = "gmcommon",
	description = "Sets the path to the garrysmod_common (https://github.com/danielga/garrysmod_common) directory",
	value = "path to garrysmod_common directory"
})

local gmcommon = _OPTIONS.gmcommon or os.getenv("GARRYSMOD_COMMON")
if gmcommon == nil then
	error("you didn't provide a path to your garrysmod_common (https://github.com/danielga/garrysmod_common) directory")
end

include(gmcommon)

local CRYPTOPP_DIRECTORY = "../cryptopp"

CreateWorkspace({name = "crypt"})
	warnings("Off")

	CreateProject({serverside = true})
		IncludeLuaShared()
		defines("CRYPTOPP_ENABLE_NAMESPACE_WEAK=1")

		filter({"system:windows", "options:not compile-cryptopp"})
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			libdirs(CRYPTOPP_DIRECTORY .. "/lib")
			links("cryptopp")

		filter({"system:linux or macosx", "options:not compile-cryptopp"})
			linkoptions("-Wl,-Bstatic,-lcryptopp,-Bdynamic")

		filter("options:compile-cryptopp")
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			links("cryptopp")

	CreateProject({serverside = false})
		IncludeLuaShared()
		defines("CRYPTOPP_ENABLE_NAMESPACE_WEAK=1")

		filter({"system:windows", "options:not compile-cryptopp"})
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			libdirs(CRYPTOPP_DIRECTORY .. "/lib")
			links("cryptopp")

		filter({"system:linux or macosx", "options:not compile-cryptopp"})
			linkoptions("-Wl,-Bstatic,-lcryptopp,-Bdynamic")

		filter("options:compile-cryptopp")
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			links("cryptopp")

	if _OPTIONS["compile-cryptopp"] then
		project("cryptopp")
			kind("StaticLib")
			includedirs({
				CRYPTOPP_DIRECTORY .. "/include/cryptopp",
				CRYPTOPP_DIRECTORY .. "/src"
			})
			files({
				CRYPTOPP_DIRECTORY .. "/include/cryptopp/*.h",
				CRYPTOPP_DIRECTORY .. "/src/*.cpp"
			})
			vpaths({
				["Header files"] = CRYPTOPP_DIRECTORY .. "/*.h",
				["Source files"] = CRYPTOPP_DIRECTORY .. "/*.cpp"
			})

			filter("configurations:Release")
				defines("NDEBUG")
	end
