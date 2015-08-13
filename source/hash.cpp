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
#include <cryptopp/hmac.h>
#include <cryptopp/filters.h>

namespace hash
{

struct UserData
{
	CryptoPP::HashTransformation *hasher;
	uint8_t type;
	CryptoPP::HMAC_Base *hmac;
};

static const char *metaname = "hasher";
static const uint8_t metatype = 31;
static const char *invalid_error = "invalid hasher";
static const char *hmac_error = "this hasher doesn't support HMAC";

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
	CryptoPP::HashTransformation *hasher = GetUserData( state, index )->hasher;
	if( hasher == nullptr )
		LUA->ArgError( index, invalid_error );

	return hasher;
}

static CryptoPP::HMAC_Base *GetHMAC( lua_State *state, int32_t index )
{
	UserData *udata = GetUserData( state, index );
	if( udata->hasher == nullptr )
		LUA->ArgError( index, invalid_error );

	CryptoPP::HMAC_Base *hmac = udata->hmac;
	if( hmac == nullptr )
		LUA->ArgError( index, hmac_error );

	return hmac;
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
	CryptoPP::HashTransformation *hasher = userdata->hasher;
	if( hasher == nullptr )
		return 0;

	userdata->hasher = nullptr;

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

LUA_FUNCTION_STATIC( SupportsHMAC )
{
	LUA->PushBool( GetUserData( state, 1 )->hmac != nullptr );
	return 1;
}

LUA_FUNCTION_STATIC( MinKeyLength )
{
	LUA->PushNumber( GetHMAC( state, 1 )->MinKeyLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( MaxKeyLength )
{
	LUA->PushNumber( GetHMAC( state, 1 )->MaxKeyLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( DefaultKeyLength )
{
	LUA->PushNumber( GetHMAC( state, 1 )->DefaultKeyLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( GetValidKeyLength )
{
	LUA->PushNumber( GetHMAC( state, 1 )->GetValidKeyLength(
		static_cast<size_t>( LUA->CheckNumber( 2 ) )
	) );
	return 1;
}

LUA_FUNCTION_STATIC( SetKey )
{
	CryptoPP::HMAC_Base *hasher = GetHMAC( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t keylen = 0;
	const uint8_t *key = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &keylen ) );

	try
	{
		hasher->SetKey( key, keylen );
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

LUA_FUNCTION_STATIC( HMAC )
{
	CryptoPP::HMAC_Base *hasher = GetHMAC( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t datalen = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &datalen ) );

	try
	{
		std::string mac;
		CryptoPP::StringSource( data, datalen, true, new CryptoPP::HashFilter(
			*hasher,
			new CryptoPP::StringSink( mac )
		) );

		LUA->PushString( mac.c_str( ), mac.size( ) );
		return 1;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushNil( );
		LUA->PushString( e.what( ) );
	}

	return 2;
}

LUA_FUNCTION_STATIC( VerifyHMAC )
{
	CryptoPP::HMAC_Base *hasher = GetHMAC( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 3, GarrysMod::Lua::Type::STRING );

	uint32_t datalen = 0;
	const char *data = LUA->GetString( 2, &datalen );

	uint32_t maclen = 0;
	const char *mac = LUA->GetString( 3, &maclen );

	if( maclen != hasher->DigestSize( ) )
		LUA->ThrowError( "digest size is not of the required size" );

	try
	{
		std::string sdata;
		sdata.append( data, datalen );
		sdata.append( mac, maclen );

		bool result = false;
		CryptoPP::StringSource( sdata, true, new CryptoPP::HashVerificationFilter(
			*hasher,
			new CryptoPP::ArraySink( reinterpret_cast<uint8_t *>( &result ), sizeof( result ) ),
			CryptoPP::HashVerificationFilter::PUT_RESULT |
				CryptoPP::HashVerificationFilter::HASH_AT_END
		) );

		LUA->PushBool( result );
		return 1;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushNil( );
		LUA->PushString( e.what( ) );
	}

	return 2;
}

LUA_FUNCTION_STATIC( CreatorCRC32 )
{
	CryptoPP::CRC32 *hasher = new( std::nothrow ) CryptoPP::CRC32( );
	if( hasher == nullptr )
	{
		LUA->PushNil( );
		LUA->PushString( "failed to create object" );
		return 2;
	}

	void *luadata = LUA->NewUserdata( sizeof( UserData ) );
	UserData *userdata = reinterpret_cast<UserData *>( luadata );
	userdata->hasher = reinterpret_cast<CryptoPP::HMAC_Base *>( hasher );
	userdata->type = metatype;
	userdata->hmac = nullptr;

	LUA->CreateMetaTableType( metaname, metatype );
	LUA->SetMetaTable( -2 );

	LUA->CreateTable( );
	lua_setfenv( state, -2 );

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
		LUA->PushString( "failed to create hasher object" );
		return 2;
	}

	CryptoPP::HMAC<Hasher> *hmac = new( std::nothrow ) CryptoPP::HMAC<Hasher>( );
	if( hmac == nullptr )
	{
		delete hasher;
		LUA->PushNil( );
		LUA->PushString( "failed to create HMAC object" );
		return 2;
	}

	void *luadata = LUA->NewUserdata( sizeof( UserData ) );
	UserData *userdata = reinterpret_cast<UserData *>( luadata );
	userdata->hasher = hasher;
	userdata->type = metatype;
	userdata->hmac = hmac;

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

	LUA->PushCFunction( HMAC );
	LUA->SetField( -2, "HMAC" );

	LUA->PushCFunction( VerifyHMAC );
	LUA->SetField( -2, "VerifyHMAC" );

	LUA->Pop( 1 );

	LUA->PushCFunction( CreatorCRC32 );
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
