#include <GarrysMod/Lua/Interface.h>
#include <crypt.hpp>
#include <hash.hpp>
#include <hmac.hpp>
#include <cryptopp/osrng.h>

static const char *tablename = "crypt";

LUA_FUNCTION_STATIC( GenerateRandomBytes )
{
	CryptoPP::SecByteBlock key( static_cast<size_t>( LUA->CheckNumber( 1 ) ) );
	CryptoPP::AutoSeededRandomPool( ).GenerateBlock( key, key.size( ) );
	LUA->PushString( reinterpret_cast<char *>( key.data( ) ), key.size( ) );
	return 1;
}

GMOD_MODULE_OPEN( )
{
	LUA->CreateTable( );

	LUA->PushString( "crypt 1.1.4" );
	LUA->SetField( -2, "Version" );

	// version num follows LuaJIT style, xx.yy.zz
	LUA->PushNumber( 10104 );
	LUA->SetField( -2, "VersionNum" );

	LUA->PushCFunction( GenerateRandomBytes );
	LUA->SetField( -2, "GenerateRandomBytes" );

	crypt::Initialize( LUA );
	hash::Initialize( LUA );
	hmac::Initialize( LUA );

	LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, tablename );
	return 0;
}

GMOD_MODULE_CLOSE( )
{
	LUA->PushNil( );
	LUA->SetField( GarrysMod::Lua::INDEX_GLOBAL, tablename );

	hmac::Deinitialize( LUA );
	hash::Deinitialize( LUA );
	crypt::Deinitialize( LUA );
	return 0;
}
