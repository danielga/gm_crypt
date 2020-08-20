PROJECT_GENERATOR_VERSION = 2

newoption({
	trigger = "compile-cryptopp",
	description = "Compile cryptopp along with the modules"
})

newoption({
	trigger = "gmcommon",
	description = "Sets the path to the garrysmod_common (https://github.com/danielga/garrysmod_common) directory",
	value = "path to garrysmod_common directory"
})

local gmcommon = assert(_OPTIONS.gmcommon or os.getenv("GARRYSMOD_COMMON"),
	"you didn't provide a path to your garrysmod_common (https://github.com/danielga/garrysmod_common) directory")
include(gmcommon)

local SOURCE_DIRECTORY = "source"
local CRYPTOPP_DIRECTORY = "cryptopp"

CreateWorkspace({name = "crypt"})
	warnings("Off")

	CreateProject({serverside = true, manual_files = true})
		IncludeLuaShared()
		defines("CRYPTOPP_ENABLE_NAMESPACE_WEAK=1")
		includedirs({
			SOURCE_DIRECTORY .. "/common",
			SOURCE_DIRECTORY .. "/module"
		})
		files({
			SOURCE_DIRECTORY .. "/common/*.hpp",
			SOURCE_DIRECTORY .. "/common/*.cpp",
			SOURCE_DIRECTORY .. "/module/*.hpp",
			SOURCE_DIRECTORY .. "/module/*.cpp"
		})

		filter({"system:windows", "options:not compile-cryptopp"})
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			libdirs(CRYPTOPP_DIRECTORY .. "/lib")
			links("cryptopp")

		filter({"system:linux or macosx", "options:not compile-cryptopp"})
			linkoptions("-Wl,-Bstatic,-lcryptopp,-Bdynamic")

		filter("options:compile-cryptopp")
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			links("cryptopp")

	CreateProject({serverside = false, manual_files = true})
		IncludeLuaShared()
		defines("CRYPTOPP_ENABLE_NAMESPACE_WEAK=1")
		includedirs({
			SOURCE_DIRECTORY .. "/common",
			SOURCE_DIRECTORY .. "/module"
		})
		files({
			SOURCE_DIRECTORY .. "/common/*.hpp",
			SOURCE_DIRECTORY .. "/common/*.cpp",
			SOURCE_DIRECTORY .. "/module/*.hpp",
			SOURCE_DIRECTORY .. "/module/*.cpp"
		})

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

	project("testing")
		kind("ConsoleApp")
		includedirs(SOURCE_DIRECTORY .. "/common")
		files({
			SOURCE_DIRECTORY .. "/common/*.hpp",
			SOURCE_DIRECTORY .. "/common/*.cpp",
			SOURCE_DIRECTORY .. "/testing/*.cpp"
		})
		vpaths({
			["Header files/*"] = SOURCE_DIRECTORY .. "/*.hpp",
			["Source files/*"] = SOURCE_DIRECTORY .. "/*.cpp"
		})

		filter({"system:windows", "options:not compile-cryptopp"})
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			libdirs(CRYPTOPP_DIRECTORY .. "/lib")
			links("cryptopp")

		filter({"system:linux or macosx", "options:not compile-cryptopp"})
			linkoptions("-Wl,-Bstatic,-lcryptopp,-Bdynamic")

		filter("options:compile-cryptopp")
			includedirs(CRYPTOPP_DIRECTORY .. "/include")
			links("cryptopp")
