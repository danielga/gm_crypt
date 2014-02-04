#dumpbin /exports lua_shared.dll > lua_shared.def
#then fix the def file with the format EXPORTS <newline> FUNC1 <newline> FUNC2 etc.
lib /def:lua_shared.def /OUT:lua_shared.lib