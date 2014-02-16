Mac was not tested at all (sorry but I'm cheap and lazy).

If stuff starts erroring or fails to work, be sure to check the correct line endings (\n and such) are present in the files for each OS.

The required Garry's Mod headers to build modules are already included as externals. Thank me later. You might also find some useful stuff there.

I've decided to not provide cryptopp's libraries and headers as it just clogs up the repository. On Windows, just create a folder inside "Projects/windows" named "cryptopp" with these two folders inside: "include" and "lib". Inside "include" you create another folder called "cryptopp" and you place all of cryptopp's headers there. Inside the "lib" folder you create two more folders called "release" and "debug" (the "debug" one is optional, you don't need it if you don't intend to debug gm_crypt). If you know a bit about programming, you'll realise that inside "lib/release" you'll place the static release build of cryptopp and inside "lib/debug" the static debug build.