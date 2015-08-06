# gm_crypt

A cryptography module for the game Garry's Mod that uses [Crypto++][1].

## Info

Mac was not tested at all (sorry but I'm poor).

If stuff starts erroring or fails to work, be sure to check the correct line endings (\n and such) are present in the files for each OS.

This project requires [garrysmod_common][2], a framework to facilitate the creation of compilations files (Visual Studio, make, XCode, etc). Simply set the environment variable 'GARRYSMOD_COMMON' or the premake option 'gmcommon' to the path of your local copy of [garrysmod_common][2].

I've decided to not provide cryptopp's libraries and headers as it just clogs up the repository. On Windows, just create a folder inside "projects/windows" named "cryptopp" with these two folders inside: "include" and "lib". Inside "include" you create another folder called "cryptopp" and you place all of cryptopp's headers there. Inside the "lib" folder you'll place the static release build of cryptopp. On Linux, just get the libcryptopp/++ package. On Mac, you'll probably get some luck with a package manager that'll (with some luck) provide you an environment similar to Linux.

Another option available for all platforms is compiling cryptopp before linking each module to it. Just add the --compile-cryptopp premake flag and premake will create a project for cryptopp which will be imported by the modules.


  [1]: http://www.cryptopp.com
  [2]: https://bitbucket.org/danielga/garrysmod_common
