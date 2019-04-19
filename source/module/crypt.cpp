#include <crypt.hpp>
#include <cryptography.hpp>
#include <GarrysMod/Lua/Interface.h>

namespace crypt
{

static const char *metaname = "crypter";
static int32_t metatype = GarrysMod::Lua::Type::NONE;
static const char *invalid_error = "invalid crypter";

inline void CheckType( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	if( !LUA->IsType( index, metatype ) )
		LUA->TypeError( index, metaname );
}

static cryptography::Crypter *GetUserData( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	CheckType( LUA, index );
	return  LUA->GetUserType<cryptography::Crypter>( index, metatype );
}

static cryptography::Crypter *Get( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	cryptography::Crypter *crypter = GetUserData( LUA, index );
	if( crypter == nullptr )
		LUA->ArgError( index, invalid_error );

	return crypter;
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
	cryptography::Crypter *crypter = GetUserData( LUA, 1 );
	if( crypter == nullptr )
		return 0;

	try
	{
		delete crypter;
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

LUA_FUNCTION_STATIC( AlgorithmName )
{
	LUA->PushString( Get( LUA, 1 )->AlgorithmName( ).c_str( ) );
	return 1;
}

LUA_FUNCTION_STATIC( MaxPlaintextLength )
{
	LUA->PushNumber( Get( LUA, 1 )->MaxPlaintextLength( static_cast<size_t>(
		LUA->CheckNumber( 2 )
	) ) );
	return 1;
}

LUA_FUNCTION_STATIC( CiphertextLength )
{
	LUA->PushNumber( Get( LUA, 1 )->CiphertextLength( static_cast<size_t>(
		LUA->CheckNumber( 2 )
	) ) );
	return 1;
}

LUA_FUNCTION_STATIC( FixedMaxPlaintextLength )
{
	LUA->PushNumber( Get( LUA, 1 )->FixedMaxPlaintextLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( FixedCiphertextLength )
{
	LUA->PushNumber( Get( LUA, 1 )->FixedCiphertextLength( ) );
	return 1;
}

LUA_FUNCTION_STATIC( GetValidPrimaryKeyLength )
{
	LUA->PushNumber( Get( LUA, 1 )->GetValidPrimaryKeyLength( static_cast<size_t>(
		LUA->CheckNumber( 2 )
	) ) );
	return 1;
}

LUA_FUNCTION_STATIC( GeneratePrimaryKey )
{
	cryptography::Crypter *crypter = Get( LUA, 1 );
	size_t keySize = static_cast<size_t>( LUA->CheckNumber( 2 ) );

	cryptography::bytes priKey = crypter->GeneratePrimaryKey( keySize );
	if( priKey.empty( ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( reinterpret_cast<const char *>( priKey.data( ) ), priKey.size( ) );
	return 1;
}

LUA_FUNCTION_STATIC( SetPrimaryKey )
{
	cryptography::Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t priLen = 0;
	const uint8_t *priKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &priLen ) );

	cryptography::bytes privKey( priKey, priKey + priLen );
	if( !crypter->SetPrimaryKey( privKey ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushBool( true );
	return 1;
}

LUA_FUNCTION_STATIC( GetValidSecondaryKeyLength )
{
	LUA->PushNumber( Get( LUA, 1 )->GetValidSecondaryKeyLength( static_cast<size_t>(
		LUA->CheckNumber( 2 )
	) ) );
	return 1;
}

LUA_FUNCTION_STATIC( GenerateSecondaryKey )
{
	cryptography::Crypter *crypter = Get( LUA, 1 );

	if( !LUA->IsType( 2, GarrysMod::Lua::Type::NUMBER ) &&
		!LUA->IsType( 2, GarrysMod::Lua::Type::STRING ) )
		LUA->TypeError( 2, "number or string" );

	cryptography::bytes secKey;
	if( LUA->IsType( 2, GarrysMod::Lua::Type::STRING ) )
	{
		size_t priLen = 0;
		const uint8_t *priKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &priLen ) );
		cryptography::bytes privKey( priKey, priKey + priLen );
		secKey = crypter->GenerateSecondaryKey( privKey );
	}
	else
		secKey = crypter->GenerateSecondaryKey( static_cast<size_t>( LUA->CheckNumber( 2 ) ) );

	if( secKey.empty( ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}
	
	LUA->PushString( reinterpret_cast<const char *>( secKey.data( ) ), secKey.size( ) );
	return 1;
}

LUA_FUNCTION_STATIC( SetSecondaryKey )
{
	cryptography::Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t secLen = 0;
	const uint8_t *secKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &secLen ) );

	cryptography::bytes secoKey( secKey, secKey + secLen );
	if( !crypter->SetSecondaryKey( secoKey ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushBool( true );
	return 1;
}

LUA_FUNCTION_STATIC( Decrypt )
{
	cryptography::Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	cryptography::bytes encrypted( data, data + len );
	cryptography::bytes decrypted;
	if( !crypter->Decrypt( encrypted, decrypted ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( reinterpret_cast<const char *>( decrypted.data( ) ), decrypted.size( ) );
	return 1;
}

LUA_FUNCTION_STATIC( Encrypt )
{
	cryptography::Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	cryptography::bytes decrypted( data, data + len );
	cryptography::bytes encrypted;
	if( !crypter->Encrypt( decrypted, encrypted ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( reinterpret_cast<const char *>( encrypted.data( ) ), encrypted.size( ) );
	return 1;
}

template<typename Crypter>
static int Creator( lua_State *state ) GMOD_NOEXCEPT
{
	GarrysMod::Lua::ILuaBase *LUA = state->luabase;
	LUA->SetState( state );

	Crypter *crypter = new( std::nothrow ) Crypter( );
	if( crypter == nullptr )
	{
		LUA->PushNil( );
		LUA->PushString( "failed to create object" );
		return 2;
	}

	LUA->PushUserType( crypter, metatype );

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

	LUA->PushCFunction( AlgorithmName );
	LUA->SetField( -2, "AlgorithmName" );

	LUA->PushCFunction( MaxPlaintextLength );
	LUA->SetField( -2, "MaxPlaintextLength" );

	LUA->PushCFunction( CiphertextLength );
	LUA->SetField( -2, "CiphertextLength" );

	LUA->PushCFunction( FixedMaxPlaintextLength );
	LUA->SetField( -2, "FixedMaxPlaintextLength" );

	LUA->PushCFunction( FixedCiphertextLength );
	LUA->SetField( -2, "FixedCiphertextLength" );

	LUA->PushCFunction( GetValidPrimaryKeyLength );
	LUA->SetField( -2, "GetValidPrimaryKeyLength" );

	LUA->PushCFunction( GeneratePrimaryKey );
	LUA->SetField( -2, "GeneratePrimaryKey" );

	LUA->PushCFunction( SetPrimaryKey );
	LUA->SetField( -2, "SetPrimaryKey" );

	LUA->PushCFunction( GetValidSecondaryKeyLength );
	LUA->SetField( -2, "GetValidSecondaryKeyLength" );

	LUA->PushCFunction( GenerateSecondaryKey );
	LUA->SetField( -2, "GenerateSecondaryKey" );

	LUA->PushCFunction( SetSecondaryKey );
	LUA->SetField( -2, "SetSecondaryKey" );

	LUA->PushCFunction( Decrypt );
	LUA->SetField( -2, "Decrypt" );

	LUA->PushCFunction( Encrypt );
	LUA->SetField( -2, "Encrypt" );

	LUA->Pop( 1 );

	LUA->PushCFunction( Creator<cryptography::AES> );
	LUA->SetField( -2, "AES" );

	LUA->PushCFunction( Creator<cryptography::RSA> );
	LUA->SetField( -2, "RSA" );

	LUA->PushCFunction( Creator<cryptography::ECP> );
	LUA->SetField( -2, "ECP" );
}

void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	LUA->PushNil( );
	LUA->SetField( GarrysMod::Lua::INDEX_REGISTRY, metaname );
}

}
