#include <GarrysMod/Lua/Interface.h>
#include <crypt.hpp>
#include <hash.hpp>

static const char *tablename = "crypt";

GMOD_MODULE_OPEN( )
{
	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->CreateTable( );

	LUA->PushString( "1.0.2" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xx.yy.zz
	LUA->PushNumber( 10002 );
	LUA->SetField( -2, "VersionNum" );

	crypt::Initialize( state );
	hash::Initialize( state );

	LUA->SetField( -2, tablename );

	LUA->Pop( 1 );
	return 0;
}

GMOD_MODULE_CLOSE( )
{
	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->PushNil( );
	LUA->SetField( -2, tablename );

	LUA->Pop( 1 );
	return 0;
}
