#include <hmac.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/Lua/LuaInterface.h>
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
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>

namespace hmac
{

static const char *metaname = "hmac";
static int32_t metatype = GarrysMod::Lua::Type::NONE;
static const char *invalid_error = "invalid hmac";
static const char *table_name = "hmac";

inline void CheckType( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	if( !LUA->IsType( index, metatype ) )
		LUA->TypeError( index, metaname );
}

static CryptoPP::HMAC_Base *GetUserData( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	CheckType( LUA, index );
	return LUA->GetUserType<CryptoPP::HMAC_Base>( index, metatype );
}

static CryptoPP::HMAC_Base *Get( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	CryptoPP::HMAC_Base *hmac = GetUserData( LUA, index );
	if( hmac == nullptr )
		LUA->ArgError( index, invalid_error );

	return hmac;
}

LUA_FUNCTION_STATIC( tostring )
{

#if defined _WIN32

	LUA->PushFormattedString( "%s: %p", metaname, Get( LUA, 1 ) );

#elif defined __linux || defined __APPLE__

	LUA->PushFormattedString( "%s: 0x%p", metaname, Get( LUA, 1 ) );

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

	LUA->GetFEnv( 1 );
	LUA->Push( 2 );
	LUA->RawGet( -2 );
	return 1;
}

LUA_FUNCTION_STATIC( newindex )
{
	CheckType( LUA, 1 );

	LUA->GetFEnv( 1 );
	LUA->Push( 2 );
	LUA->Push( 3 );
	LUA->RawSet( -3 );
	return 0;
}

LUA_FUNCTION_STATIC( gc )
{
	CryptoPP::HMAC_Base *hmac = GetUserData( LUA, 1 );
	if( hmac == nullptr )
		return 0;

	try
	{
		delete hmac;
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
	CryptoPP::HMAC_Base *hmac = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	try
	{
		hmac->Update( data, len );

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
	CryptoPP::HMAC_Base *hmac = Get( LUA, 1 );

	try
	{
		uint32_t size = hmac->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = digest.data( );

		hmac->Final( digestptr );

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
	CryptoPP::HMAC_Base *hmac = Get( LUA, 1 );

	try
	{
		hmac->Restart( );

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
	CryptoPP::HMAC_Base *hmac = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	try
	{
		uint32_t size = hmac->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = digest.data( );

		hmac->CalculateDigest( digestptr, data, len );

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

LUA_FUNCTION_STATIC( MinKeyLength )
{
	LUA->PushNumber( Get( LUA, 1 )->MinKeyLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( MaxKeyLength )
{
	LUA->PushNumber( Get( LUA, 1 )->MaxKeyLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( DefaultKeyLength )
{
	LUA->PushNumber( Get( LUA, 1 )->DefaultKeyLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( GetValidKeyLength )
{
	LUA->PushNumber( Get( LUA, 1 )->GetValidKeyLength(
		static_cast<size_t>( LUA->CheckNumber( 2 ) )
	) );
	return 1;
}

LUA_FUNCTION_STATIC( SetKey )
{
	CryptoPP::HMAC_Base *hmac = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t keylen = 0;
	const uint8_t *key = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &keylen ) );

	try
	{
		hmac->SetKey( key, keylen );
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

template<typename Hasher, bool Secure = true>
static int Creator( lua_State *state )
{
	GarrysMod::Lua::ILuaBase *LUA = state->luabase;
	LUA->SetState( state );

	// let's annoy everyone to force them to drop insecure algorithms
	if( !Secure )
		static_cast<GarrysMod::Lua::ILuaInterface *>( LUA )->ErrorNoHalt(
			"[gm_crypt] %s HMAC algorithm is considered insecure!\n",
			Hasher::StaticAlgorithmName( )
		);

	CryptoPP::HMAC<Hasher> *hmac = new( std::nothrow ) CryptoPP::HMAC<Hasher>( );
	if( hmac == nullptr )
	{
		LUA->PushNil( );
		LUA->PushString( "failed to create HMAC object" );
		return 2;
	}

	CryptoPP::SecByteBlock key( hmac->GetValidKeyLength( 16 ) );
	CryptoPP::AutoSeededRandomPool( ).GenerateBlock( key.data( ), key.size( ) );
	hmac->SetKey( key.data( ), key.size( ) );

	LUA->PushUserType( hmac, metatype );

	LUA->PushMetaTable( metatype );
	LUA->SetMetaTable( -2 );

	LUA->CreateTable( );
	LUA->SetFEnv( -2 );

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

	LUA->PushCFunction( MinKeyLength );
	LUA->SetField( -2, "MinKeyLength" );

	LUA->PushCFunction( MaxKeyLength );
	LUA->SetField( -2, "MaxKeyLength" );

	LUA->PushCFunction( DefaultKeyLength );
	LUA->SetField( -2, "DefaultKeyLength" );

	LUA->PushCFunction( GetValidKeyLength );
	LUA->SetField( -2, "GetValidKeyLength" );

	LUA->PushCFunction( SetKey );
	LUA->SetField( -2, "SetKey" );

	LUA->Pop( 1 );

	LUA->CreateTable( );

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

	LUA->SetField( -2, table_name );
}

void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	LUA->PushNil( );
	LUA->SetField( GarrysMod::Lua::INDEX_REGISTRY, metaname );
}

}
