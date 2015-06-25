gm_crypt
========

A cryptography module for the game Garry's Mod.

Info
-------

Mac was not tested at all (sorry but I'm cheap and lazy).

If stuff starts erroring or fails to work, be sure to check the correct line endings (\n and such) are present in the files for each OS.

This project requires garrysmod_common (https://bitbucket.org/danielga/garrysmod_common), a framework to facilitate the creation of compilations files (Visual Studio, make, XCode, etc). Simply set the environment variable 'GARRYSMOD_COMMON' or the premake option 'gmcommon' to the path of your local copy of garrysmod_common.

I've decided to not provide cryptopp's libraries and headers as it just clogs up the repository. On Windows, just create a folder inside "Projects/windows" named "cryptopp" with these two folders inside: "include" and "lib". Inside "include" you create another folder called "cryptopp" and you place all of cryptopp's headers there. Inside the "lib" folder you'll place the static release build of cryptopp. On Linux, just get the libcryptopp/++ package. On Mac, you'll probably get some luck with a package manager that'll (with some luck) provide you an environment similar to Linux.

Another option available for all platforms is compiling cryptopp before linking each module to it. Just create a folder named cryptopp inside the "Projects" folder with two folders inside named "include" and "src". Inside the src folder you'll place all the REQUIRED source files. Inside the "include" folder, you'll place all the REQUIRED header files. This is a bit complicated but is useful for Windows.