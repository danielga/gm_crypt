#include <hash.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
#include <lua.hpp>
#include <cstdint>
#include <vector>
#include <cryptopp/crc.h>
#include <cryptopp/sha.h>
#include <cryptopp/tiger.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/ripemd.h>

namespace hash
{

struct UserData
{
	CryptoPP::HashTransformation *data;
	uint8_t type;
};

static const char *metaname = "hasher";
static const uint8_t metatype = 31;
static const char *invalid_error = "invalid hasher";

inline void CheckType( lua_State *state, int32_t index )
{
	if( !LUA->IsType( index, metatype ) )
		luaL_typerror( state, index, metaname );
}

static UserData *GetUserData( lua_State *state, int32_t index )
{
	CheckType( state, index );
	return static_cast<UserData *>( LUA->GetUserdata( index ) );
}

static CryptoPP::HashTransformation *Get( lua_State *state, int32_t index )
{
	CryptoPP::HashTransformation *hasher = static_cast<UserData *>( GetUserData( state, index ) )->data;
	if( hasher == nullptr )
		LUA->ArgError( index, invalid_error );

	return hasher;
}

LUA_FUNCTION_STATIC( tostring )
{

#if defined _WIN32

	lua_pushfstring( state, "%s: %p", metaname, Get( state, 1 ) );

#elif defined __linux || defined __APPLE__

	lua_pushfstring( state, "%s: 0x%p", metaname, Get( state, 1 ) );

#endif

	return 1;
}

LUA_FUNCTION_STATIC( eq )
{
	LUA->PushBool( Get( state, 1 ) == Get( state, 2 ) );
	return 1;
}

LUA_FUNCTION_STATIC( index )
{
	CheckType( state, 1 );

	LUA->CreateMetaTableType( metaname, metatype );
	LUA->Push( 2 );
	LUA->RawGet( -2 );
	if( !LUA->IsType( -1, GarrysMod::Lua::Type::NIL ) )
		return 1;

	LUA->Pop( 2 );

	lua_getfenv( state, 1 );
	LUA->Push( 2 );
	LUA->RawGet( -2 );
	return 1;
}

LUA_FUNCTION_STATIC( newindex )
{
	CheckType( state, 1 );

	lua_getfenv( state, 1 );
	LUA->Push( 2 );
	LUA->Push( 3 );
	LUA->RawSet( -3 );
	return 0;
}

LUA_FUNCTION_STATIC( gc )
{
	UserData *userdata = GetUserData( state, 1 );
	CryptoPP::HashTransformation *hasher = userdata->data;
	if( hasher == nullptr )
		return 0;

	userdata->data = nullptr;

	try
	{
		delete hasher;
		return 0;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return 1;
}

LUA_FUNCTION_STATIC( Update )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	try
	{
		hasher->Update( data, len );

		LUA->PushBool( true );
		return 1;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushNil( );
		LUA->PushString( e.what( ) );
	}

	return 2;
}

LUA_FUNCTION_STATIC( Final )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );

	try
	{
		uint32_t size = hasher->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = digest.data( );

		hasher->Final( digestptr );

		LUA->PushString( reinterpret_cast<const char *>( digestptr ), size );
		return 1;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushNil( );
		LUA->PushString( e.what( ) );
	}

	return 2;
}

LUA_FUNCTION_STATIC( Restart )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );

	try
	{
		hasher->Restart( );

		LUA->PushBool( true );
		return 1;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushNil( );
		LUA->PushString( e.what( ) );
	}

	return 2;
}

LUA_FUNCTION_STATIC( Digest )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	try
	{
		uint32_t size = hasher->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = digest.data( );

		hasher->CalculateDigest( digestptr, data, len );

		LUA->PushString( reinterpret_cast<const char *>( digestptr ), size );
		return 1;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushNil( );
		LUA->PushString( e.what( ) );
	}

	return 2;
}

LUA_FUNCTION_STATIC( Name )
{
	LUA->PushString( Get( state, 1 )->AlgorithmName( ).c_str( ) );
	return 1;
}

LUA_FUNCTION_STATIC( Size )
{
	LUA->PushNumber( Get( state, 1 )->DigestSize( ) );
	return 1;
}

LUA_FUNCTION_STATIC( BlockSize )
{
	LUA->PushNumber( Get( state, 1 )->OptimalBlockSize( ) );
	return 1;
}

template<typename Hasher, bool Secure = true>
LUA_FUNCTION_STATIC( Creator )
{
	// let's annoy everyone to force them to drop insecure algorithms
	if( !Secure )
		static_cast<GarrysMod::Lua::ILuaInterface *>( LUA )->ErrorNoHalt(
			"[gm_crypt] %s hashing algorithm is considered insecure!\n",
			Hasher::StaticAlgorithmName( )
		);

	Hasher *hasher = new( std::nothrow ) Hasher( );
	if( hasher == nullptr )
	{
		LUA->PushNil( );
		LUA->PushString( "failed to create object" );
		return 2;
	}

	void *luadata = LUA->NewUserdata( sizeof( UserData ) );
	UserData *userdata = reinterpret_cast<UserData *>( luadata );
	userdata->data = hasher;
	userdata->type = metatype;

	LUA->CreateMetaTableType( metaname, metatype );
	LUA->SetMetaTable( -2 );

	LUA->CreateTable( );
	lua_setfenv( state, -2 );

	return 1;
}

void Initialize( lua_State *state )
{
	LUA->CreateMetaTableType( metaname, metatype );

	LUA->Push( -1 );
	LUA->SetField( -2, "__metatable" );

	LUA->PushCFunction( tostring );
	LUA->SetField( -2, "__tostring" );

	LUA->PushCFunction( eq );
	LUA->SetField( -2, "__eq" );

	LUA->PushCFunction( index );
	LUA->SetField( -2, "__index" );

	LUA->PushCFunction( newindex );
	LUA->SetField( -2, "__newindex" );

	LUA->PushCFunction( gc );
	LUA->SetField( -2, "__gc" );

	LUA->PushCFunction( gc );
	LUA->SetField( -2, "Destroy" );

	LUA->PushCFunction( Update );
	LUA->SetField( -2, "Update" );

	LUA->PushCFunction( Final );
	LUA->SetField( -2, "Final" );

	LUA->PushCFunction( Restart );
	LUA->SetField( -2, "Restart" );

	LUA->PushCFunction( Digest );
	LUA->SetField( -2, "CalculateDigest" );

	LUA->PushCFunction( Name );
	LUA->SetField( -2, "AlgorythmName" );

	LUA->PushCFunction( Size );
	LUA->SetField( -2, "DigestSize" );

	LUA->PushCFunction( BlockSize );
	LUA->SetField( -2, "OptimalBlockSize" );

	LUA->Pop( 1 );

	LUA->PushCFunction( Creator<CryptoPP::CRC32> );
	LUA->SetField( -2, "CRC32" );

	LUA->PushCFunction( Creator<CryptoPP::SHA1> );
	LUA->SetField( -2, "SHA1" );

	LUA->PushCFunction( Creator<CryptoPP::SHA224> );
	LUA->SetField( -2, "SHA224" );

	LUA->PushCFunction( Creator<CryptoPP::SHA256> );
	LUA->SetField( -2, "SHA256" );

	LUA->PushCFunction( Creator<CryptoPP::SHA384> );
	LUA->SetField( -2, "SHA384" );

	LUA->PushCFunction( Creator<CryptoPP::SHA512> );
	LUA->SetField( -2, "SHA512" );

	LUA->PushCFunction( Creator<CryptoPP::Tiger> );
	LUA->SetField( -2, "Tiger" );

	LUA->PushCFunction( Creator<CryptoPP::Whirlpool> );
	LUA->SetField( -2, "Whirlpool" );

	LUA->PushCFunction( Creator<CryptoPP::Weak::MD2, false> );
	LUA->SetField( -2, "MD2" );

	LUA->PushCFunction( Creator<CryptoPP::Weak::MD4, false> );
	LUA->SetField( -2, "MD4" );

	LUA->PushCFunction( Creator<CryptoPP::Weak::MD5, false> );
	LUA->SetField( -2, "MD5" );

	LUA->PushCFunction( Creator<CryptoPP::RIPEMD128, false> );
	LUA->SetField( -2, "RIPEMD128" );

	LUA->PushCFunction( Creator<CryptoPP::RIPEMD160> );
	LUA->SetField( -2, "RIPEMD160" );

	LUA->PushCFunction( Creator<CryptoPP::RIPEMD256, false> );
	LUA->SetField( -2, "RIPEMD256" );

	LUA->PushCFunction( Creator<CryptoPP::RIPEMD320> );
	LUA->SetField( -2, "RIPEMD320" );
}

}