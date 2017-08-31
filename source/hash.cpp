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

static const char *metaname = "hasher";
static int32_t metatype = GarrysMod::Lua::Type::NONE;
static const char *invalid_error = "invalid hasher";

inline void CheckType( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	if( !LUA->IsType( index, metatype ) )
		luaL_typerror( LUA->GetState( ), index, metaname );
}

static CryptoPP::HashTransformation *GetUserData( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	CheckType( LUA, index );
	return LUA->GetUserType<CryptoPP::HashTransformation>( index, metatype );
}

static CryptoPP::HashTransformation *Get( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	CryptoPP::HashTransformation *hasher = GetUserData( LUA, index );
	if( hasher == nullptr )
		LUA->ArgError( index, invalid_error );

	return hasher;
}

LUA_FUNCTION_STATIC( tostring )
{

#if defined _WIN32

	lua_pushfstring( LUA->GetState( ), "%s: %p", metaname, Get( LUA, 1 ) );

#elif defined __linux || defined __APPLE__

	lua_pushfstring( LUA->GetState( ), "%s: 0x%p", metaname, Get( LUA, 1 ) );

#endif

	return 1;
}

LUA_FUNCTION_STATIC( eq )
{
	LUA->PushBool( Get( LUA, 1 ) == Get( LUA, 2 ) );
	return 1;
}

LUA_FUNCTION_STATIC( index )
{
	CheckType( LUA, 1 );

	LUA->PushMetaTable( metatype );
	LUA->Push( 2 );
	LUA->RawGet( -2 );
	if( !LUA->IsType( -1, GarrysMod::Lua::Type::NIL ) )
		return 1;

	LUA->Pop( 2 );

	lua_getfenv( LUA->GetState( ), 1 );
	LUA->Push( 2 );
	LUA->RawGet( -2 );
	return 1;
}

LUA_FUNCTION_STATIC( newindex )
{
	CheckType( LUA, 1 );

	lua_getfenv( LUA->GetState( ), 1 );
	LUA->Push( 2 );
	LUA->Push( 3 );
	LUA->RawSet( -3 );
	return 0;
}

LUA_FUNCTION_STATIC( gc )
{
	CryptoPP::HashTransformation *hasher = GetUserData( LUA, 1 );
	if( hasher == nullptr )
		return 0;

	try
	{
		delete hasher;
		LUA->SetUserType( 1, nullptr );
		return 0;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return 1;
}

LUA_FUNCTION_STATIC( IsValid )
{
	LUA->PushBool( GetUserData( LUA, 1 ) != nullptr );
	return 1;
}

LUA_FUNCTION_STATIC( Update )
{
	CryptoPP::HashTransformation *hasher = Get( LUA, 1 );
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
	CryptoPP::HashTransformation *hasher = Get( LUA, 1 );

	try
	{
		uint32_t size = hasher->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = digest.data( );

		hasher->Final( digestptr );

		LUA->PushString( reinterpret_cast<char *>( digestptr ), size );
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
	CryptoPP::HashTransformation *hasher = Get( LUA, 1 );

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

LUA_FUNCTION_STATIC( CalculateDigest )
{
	CryptoPP::HashTransformation *hasher = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	try
	{
		uint32_t size = hasher->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = digest.data( );

		hasher->CalculateDigest( digestptr, data, len );

		LUA->PushString( reinterpret_cast<char *>( digestptr ), size );
		return 1;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushNil( );
		LUA->PushString( e.what( ) );
	}

	return 2;
}

LUA_FUNCTION_STATIC( AlgorithmName )
{
	LUA->PushString( Get( LUA, 1 )->AlgorithmName( ).c_str( ) );
	return 1;
}

LUA_FUNCTION_STATIC( DigestSize )
{
	LUA->PushNumber( Get( LUA, 1 )->DigestSize( ) );
	return 1;
}

LUA_FUNCTION_STATIC( OptimalBlockSize )
{
	LUA->PushNumber( Get( LUA, 1 )->OptimalBlockSize( ) );
	return 1;
}

template<typename Hasher, bool Secure = true>
static int Creator( lua_State *state ) GMOD_NOEXCEPT
{
	GarrysMod::Lua::ILuaBase *LUA = state->luabase;
	LUA->SetState( state );

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

	LUA->PushUserType( hasher, metatype );

	LUA->PushMetaTable( metatype );
	LUA->SetMetaTable( -2 );

	LUA->CreateTable( );
	lua_setfenv( state, -2 );

	return 1;
}

void Initialize( GarrysMod::Lua::ILuaBase *LUA )
{
	metatype = LUA->CreateMetaTable( metaname );

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

	LUA->PushCFunction( IsValid );
	LUA->SetField( -2, "IsValid" );

	LUA->PushCFunction( Update );
	LUA->SetField( -2, "Update" );

	LUA->PushCFunction( Final );
	LUA->SetField( -2, "Final" );

	LUA->PushCFunction( Restart );
	LUA->SetField( -2, "Restart" );

	LUA->PushCFunction( CalculateDigest );
	LUA->SetField( -2, "CalculateDigest" );

	LUA->PushCFunction( AlgorithmName );
	LUA->SetField( -2, "AlgorithmName" );

	LUA->PushCFunction( DigestSize );
	LUA->SetField( -2, "DigestSize" );

	LUA->PushCFunction( OptimalBlockSize );
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

void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	LUA->PushNil( );
	LUA->SetField( GarrysMod::Lua::INDEX_REGISTRY, metaname );
}

}
