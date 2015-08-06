#include <crypt.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <lua.hpp>
#include <cstdint>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>

namespace crypt
{

class Crypter
{
public:
	virtual bool GeneratePrimaryKey( uint32_t priSize, std::string &priKey, bool use ) = 0;

	virtual bool SetPrimaryKey( const uint8_t *priKey, uint32_t priSize ) = 0;

	virtual bool GenerateSecondaryKey(
		const uint8_t *priKey,
		uint32_t priSize,
		uint32_t secSize,
		std::string &secKey,
		bool use
	) = 0;

	virtual bool SetSecondaryKey( const uint8_t *secKey, uint32_t secSize ) = 0;

	virtual bool Decrypt( const uint8_t *data, size_t len, std::string &decrypted ) = 0;

	virtual bool Encrypt( const uint8_t *data, size_t len, std::string &encrypted ) = 0;

	virtual const std::string &GetLastError( ) const = 0;
};

class AES : public Crypter
{
public:
	bool GeneratePrimaryKey( uint32_t priSize, std::string &priKey, bool use )
	{
		if( priSize != 16 && priSize != 24 && priSize != 32 )
			return false;

		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			uint8_t key[32] = { 0 };
			prng.GenerateBlock( key, priSize );

			CryptoPP::StringSource( key, priSize, true, new CryptoPP::StringSink( priKey ) );

			if( use )
			{
				decryptor.SetKey( key, priSize );
				encryptor.SetKey( key, priSize );
			}
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool SetPrimaryKey( const uint8_t *priKey, uint32_t priLen )
	{
		if( priLen != 16 && priLen != 24 && priLen != 32 )
			return false;

		try
		{
			decryptor.SetKey( priKey, priLen );
			encryptor.SetKey( priKey, priLen );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool GenerateSecondaryKey( const uint8_t *, uint32_t, uint32_t secSize, std::string &secKey, bool use )
	{
		if( secSize != 16 && secSize != 24 && secSize != 32 )
			return false;

		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			uint8_t key[32] = { 0 };
			prng.GenerateBlock( key, secSize );

			CryptoPP::StringSource( key, secSize, true, new CryptoPP::StringSink( secKey ) );

			if( use )
			{
				decryptor.Resynchronize( key, secSize );
				encryptor.Resynchronize( key, secSize );
			}
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool SetSecondaryKey( const uint8_t *secKey, uint32_t secSize )
	{
		if( secSize != 16 && secSize != 24 && secSize != 32 )
			return false;

		try
		{
			decryptor.Resynchronize( secKey, secSize );
			encryptor.Resynchronize( secKey, secSize );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool Decrypt( const uint8_t *data, size_t len, std::string &decrypted )
	{
		try
		{
			CryptoPP::StringSource(
				data,
				len,
				true,
				new CryptoPP::StreamTransformationFilter(
					decryptor,
					new CryptoPP::StringSink( decrypted )
				)
			);
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool Encrypt( const uint8_t *data, size_t len, std::string &encrypted )
	{
		try
		{
			CryptoPP::StringSource(
				data,
				len,
				true,
				new CryptoPP::StreamTransformationFilter(
					encryptor,
					new CryptoPP::StringSink( encrypted )
				)
			);
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	const std::string &GetLastError( ) const
	{
		return lasterror;
	}

private:
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
	std::string lasterror;
};

class RSA : public Crypter
{
public:
	bool GeneratePrimaryKey( uint32_t priSize, std::string &priKey, bool use )
	{
		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			CryptoPP::RSA::PrivateKey privateKey;
			privateKey.GenerateRandomWithKeySize( prng, priSize );

			CryptoPP::StringSink privSink( priKey );
			privateKey.Save( privSink.Ref( ) );

			if( use )
				decryptor.AccessKey( ).AssignFrom( privateKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool SetPrimaryKey( const uint8_t *priKey, uint32_t priSize )
	{
		try
		{
			CryptoPP::RSA::PrivateKey privKey;
			CryptoPP::StringSource stringSource(
				priKey,
				priSize,
				true
			);
			privKey.Load( stringSource.Ref( ) );
			decryptor.AccessKey( ).AssignFrom( privKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool GenerateSecondaryKey( const uint8_t *priKey, uint32_t priSize, uint32_t, std::string &secKey, bool use )
	{
		try
		{
			CryptoPP::RSA::PublicKey privKey;
			CryptoPP::StringSource stringSource( priKey, priSize, true );
			privKey.Load( stringSource.Ref( ) );

			CryptoPP::RSA::PublicKey pubKey;
			pubKey.AssignFrom( privKey );
			CryptoPP::StringSink pubSink( secKey );
			pubKey.Save( pubSink.Ref( ) );

			if( use )
				encryptor.AccessKey( ).AssignFrom( pubKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool SetSecondaryKey( const uint8_t *secKey, uint32_t secSize )
	{
		try
		{
			CryptoPP::RSA::PublicKey pubKey;
			CryptoPP::StringSource stringSource( secKey, secSize, true );
			pubKey.Load( stringSource.Ref( ) );
			encryptor.AccessKey( ).AssignFrom( pubKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool Decrypt( const uint8_t *data, size_t len, std::string &decrypted )
	{
		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			CryptoPP::StringSource(
				data,
				len,
				true,
				new CryptoPP::PK_DecryptorFilter(
					prng,
					decryptor,
					new CryptoPP::StringSink( decrypted )
				)
			);
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool Encrypt( const uint8_t *data, size_t len, std::string &encrypted )
	{
		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			CryptoPP::StringSource(
				data,
				len,
				true,
				new CryptoPP::PK_EncryptorFilter(
					prng,
					encryptor,
					new CryptoPP::StringSink( encrypted )
				)
			);
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	const std::string &GetLastError( ) const
	{
		return lasterror;
	}

private:
	CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor;
	CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor;
	std::string lasterror;
};

class ECP : public Crypter
{
public:
	bool GeneratePrimaryKey( uint32_t priSize, std::string &priKey, bool use )
	{
		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privateKey;
			privateKey.GenerateRandomWithKeySize( prng, priSize );

			CryptoPP::StringSink privSink( priKey );
			privateKey.Save( privSink.Ref( ) );

			if( use )
				decryptor.AccessKey( ).AssignFrom( privateKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool SetPrimaryKey( const uint8_t *priKey, uint32_t priSize )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
			CryptoPP::StringSource stringSource(
				priKey,
				priSize,
				true
			);
			privKey.Load( stringSource.Ref( ) );
			decryptor.AccessKey( ).AssignFrom( privKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool GenerateSecondaryKey( const uint8_t *priKey, uint32_t priSize, uint32_t, std::string &secKey, bool use )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
			CryptoPP::StringSource stringSource( priKey, priSize, true );
			privKey.Load( stringSource.Ref( ) );

			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
			pubKey.AssignFrom( privKey );
			CryptoPP::StringSink pubSink( secKey );
			pubKey.Save( pubSink.Ref( ) );

			if( use )
				encryptor.AccessKey( ).AssignFrom( pubKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool SetSecondaryKey( const uint8_t *secKey, uint32_t secSize )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
			CryptoPP::StringSource stringSource( secKey, secSize, true );
			pubKey.Load( stringSource.Ref( ) );
			encryptor.AccessKey( ).AssignFrom( pubKey );
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool Decrypt( const uint8_t *data, size_t len, std::string &decrypted )
	{
		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			CryptoPP::StringSource(
				data,
				len,
				true,
				new CryptoPP::PK_DecryptorFilter(
					prng,
					decryptor,
					new CryptoPP::StringSink( decrypted )
				)
			);
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	bool Encrypt( const uint8_t *data, size_t len, std::string &encrypted )
	{
		try
		{
			CryptoPP::AutoSeededRandomPool prng;

			CryptoPP::StringSource(
				data,
				len,
				true,
				new CryptoPP::PK_EncryptorFilter(
					prng,
					encryptor,
					new CryptoPP::StringSink( encrypted )
				)
			);
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
			return false;
		}

		return true;
	}

	const std::string &GetLastError( ) const
	{
		return lasterror;
	}

private:
	CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decryptor;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encryptor;
	std::string lasterror;
};

struct UserData
{
	Crypter *data;
	uint8_t type;
};

static const char *metaname = "crypter";
static const uint8_t metatype = 30;
static const char *invalid_error = "invalid crypter";

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

static Crypter *Get( lua_State *state, int32_t index )
{
	Crypter *crypter = GetUserData( state, index )->data;
	if( crypter == nullptr )
		LUA->ArgError( index, invalid_error );

	return crypter;
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
	Crypter *crypter = userdata->data;
	if( crypter == nullptr )
		return 0;

	userdata->data = nullptr;

	try
	{
		delete crypter;
		return 0;
	}
	catch( const CryptoPP::Exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return 1;
}

LUA_FUNCTION_STATIC( GeneratePrimaryKey )
{
	Crypter *crypter = Get( state, 1 );
	uint32_t keySize = static_cast<uint32_t>( LUA->CheckNumber( 2 ) );

	bool use = true;
	if( LUA->Top( ) > 2 )
	{
		LUA->CheckType( 3, GarrysMod::Lua::Type::BOOL );
		use = LUA->GetBool( 3 );
	}

	std::string priKey;
	if( !crypter->GeneratePrimaryKey( keySize, priKey, use ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( priKey.c_str( ), priKey.size( ) );
	return 1;
}

LUA_FUNCTION_STATIC( SetPrimaryKey )
{
	Crypter *crypter = Get( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t priLen = 0;
	const uint8_t *priKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &priLen ) );

	if( !crypter->SetPrimaryKey( priKey, priLen ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushBool( true );
	return 1;
}

LUA_FUNCTION_STATIC( GenerateSecondaryKey )
{
	Crypter *crypter = Get( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );
	uint32_t keySize = static_cast<uint32_t>( LUA->CheckNumber( 3 ) );

	uint32_t priLen = 0;
	const uint8_t *priKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &priLen ) );

	bool use = true;
	if( LUA->Top( ) > 3 )
	{
		LUA->CheckType( 4, GarrysMod::Lua::Type::BOOL );
		use = LUA->GetBool( 4 );
	}

	std::string secKey;
	if( !crypter->GenerateSecondaryKey( priKey, priLen, keySize, secKey, use ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( secKey.c_str( ), secKey.size( ) );
	return 1;
}

LUA_FUNCTION_STATIC( SetSecondaryKey )
{
	Crypter *crypter = Get( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t secLen = 0;
	const uint8_t *secKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &secLen ) );

	if( !crypter->SetSecondaryKey( secKey, secLen ) )
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
	Crypter *crypter = Get( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	std::string decrypted;
	if( !crypter->Decrypt( data, len, decrypted ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( decrypted.c_str( ), decrypted.size( ) );
	return 1;
}

LUA_FUNCTION_STATIC( Encrypt )
{
	Crypter *crypter = Get( state, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	std::string encrypted;
	if( !crypter->Encrypt( data, len, encrypted ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( encrypted.c_str( ), encrypted.size( ) );
	return 1;
}

template<typename Crypter>
LUA_FUNCTION_STATIC( Creator )
{
	Crypter *crypter = new( std::nothrow ) Crypter( );
	if( crypter == nullptr )
	{
		LUA->PushNil( );
		LUA->PushString( "failed to create object" );
		return 2;
	}

	void *luadata = LUA->NewUserdata( sizeof( UserData ) );
	UserData *userdata = reinterpret_cast<UserData *>( luadata );
	userdata->data = crypter;
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

	LUA->PushCFunction( GeneratePrimaryKey );
	LUA->SetField( -2, "GeneratePrimaryKey" );

	LUA->PushCFunction( SetPrimaryKey );
	LUA->SetField( -2, "SetPrimaryKey" );

	LUA->PushCFunction( GenerateSecondaryKey );
	LUA->SetField( -2, "GenerateSecondaryKey" );

	LUA->PushCFunction( SetSecondaryKey );
	LUA->SetField( -2, "SetSecondaryKey" );

	LUA->PushCFunction( Decrypt );
	LUA->SetField( -2, "Decrypt" );

	LUA->PushCFunction( Encrypt );
	LUA->SetField( -2, "Encrypt" );

	LUA->Pop( 1 );

	LUA->PushCFunction( Creator<AES> );
	LUA->SetField( -2, "AES" );

	LUA->PushCFunction( Creator<RSA> );
	LUA->SetField( -2, "RSA" );

	LUA->PushCFunction( Creator<ECP> );
	LUA->SetField( -2, "ECP" );
}

}
