PROJECT_GENERATOR_VERSION = 2

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
		links("cryptopp")
		includedirs({
			CRYPTOPP_DIRECTORY .. "/include",
			SOURCE_DIRECTORY .. "/common",
			SOURCE_DIRECTORY .. "/module"
		})
		files({
			SOURCE_DIRECTORY .. "/common/*.hpp",
			SOURCE_DIRECTORY .. "/common/*.cpp",
			SOURCE_DIRECTORY .. "/module/*.hpp",
			SOURCE_DIRECTORY .. "/module/*.cpp"
		})

	CreateProject({serverside = false, manual_files = true})
		IncludeLuaShared()
		defines("CRYPTOPP_ENABLE_NAMESPACE_WEAK=1")
		links("cryptopp")
		includedirs({
			CRYPTOPP_DIRECTORY .. "/include",
			SOURCE_DIRECTORY .. "/common",
			SOURCE_DIRECTORY .. "/module"
		})
		files({
			SOURCE_DIRECTORY .. "/common/*.hpp",
			SOURCE_DIRECTORY .. "/common/*.cpp",
			SOURCE_DIRECTORY .. "/module/*.hpp",
			SOURCE_DIRECTORY .. "/module/*.cpp"
		})

	project("cryptopp")
		kind("StaticLib")
		vectorextensions("AVX2")
		isaextensions({"PCLMUL", "AES"})
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

		filter("system:linux or macosx")
			buildoptions("-msha")

	project("testing")
		kind("ConsoleApp")
		links("cryptopp")
		includedirs({
			CRYPTOPP_DIRECTORY .. "/include",
			SOURCE_DIRECTORY .. "/common"
		})
		files({
			SOURCE_DIRECTORY .. "/common/*.hpp",
			SOURCE_DIRECTORY .. "/common/*.cpp",
			SOURCE_DIRECTORY .. "/testing/*.cpp"
		})
		vpaths({
			["Header files/*"] = SOURCE_DIRECTORY .. "/*.hpp",
			["Source files/*"] = SOURCE_DIRECTORY .. "/*.cpp"
		})
