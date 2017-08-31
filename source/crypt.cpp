#include <crypt.hpp>
#include <GarrysMod/Lua/Interface.h>
#include <lua.hpp>
#include <cstdint>
#include <vector>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>

namespace crypt
{

typedef std::vector<uint8_t> bytes;
typedef std::basic_string< uint8_t, std::char_traits<uint8_t>, std::allocator<uint8_t> > bytes_string;
typedef CryptoPP::StringSinkTemplate<bytes_string> bytes_sink;

class Crypter
{
public:
	virtual std::string AlgorithmName( ) const = 0;

	virtual size_t MaxPlaintextLength( size_t length ) const = 0;

	virtual size_t CiphertextLength( size_t length ) const = 0;

	virtual size_t FixedMaxPlaintextLength( ) const = 0;

	virtual size_t FixedCiphertextLength( ) const = 0;

	virtual size_t GetValidPrimaryKeyLength( size_t length ) const = 0;

	virtual bool GeneratePrimaryKey( size_t priSize, bytes &priKey, bool use ) = 0;

	virtual bool SetPrimaryKey( const bytes &priKey ) = 0;

	virtual size_t GetValidSecondaryKeyLength( size_t length ) const = 0;

	virtual bool GenerateSecondaryKey(
		const bytes &priKey,
		size_t secSize,
		bytes &secKey,
		bool use
	) = 0;

	virtual bool SetSecondaryKey( const bytes &secKey ) = 0;

	virtual bool Decrypt( const bytes &data, bytes &decrypted ) = 0;

	virtual bool Encrypt( const bytes &data, bytes &encrypted ) = 0;

	virtual const std::string &GetLastError( ) const = 0;
};

class AES : public Crypter
{
public:
	std::string AlgorithmName( ) const
	{
		return encrypter.AlgorithmName( );
	}

	size_t MaxPlaintextLength( size_t length ) const
	{
		size_t remainder = length % 16;
		if( remainder == 0 )
			return length;

		return length + 16 - remainder;
	}

	size_t CiphertextLength( size_t length ) const
	{
		size_t remainder = length % 16;
		if( remainder == 0 )
			return length;

		return length + 16 - remainder;
	}

	size_t FixedMaxPlaintextLength( ) const
	{
		return 16;
	}

	size_t FixedCiphertextLength( ) const
	{
		return 16;
	}

	size_t GetValidPrimaryKeyLength( size_t length ) const
	{
		return encrypter.GetValidKeyLength( length );
	}

	bool GeneratePrimaryKey( size_t priSize, bytes &priKey, bool use )
	{
		if( !encrypter.IsValidKeyLength( priSize ) )
			return false;

		try
		{
			priKey.resize( priSize );
			CryptoPP::AutoSeededRandomPool( ).GenerateBlock( priKey.data( ), priSize );

			if( use )
				SetKey( priKey );

			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool SetPrimaryKey( const bytes &priKey )
	{
		try
		{
			SetKey( priKey );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	size_t GetValidSecondaryKeyLength( size_t length ) const
	{
		return encrypter.GetValidKeyLength( length );
	}

	bool GenerateSecondaryKey(
		const bytes &,
		size_t secSize,
		bytes &secKey,
		bool use
	)
	{
		if( !encrypter.IsValidKeyLength( secSize ) )
			return false;

		try
		{
			secKey.resize( secSize );
			CryptoPP::AutoSeededRandomPool( ).GenerateBlock( secKey.data( ), secSize );

			if( use )
				SetIV( secKey );

			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool SetSecondaryKey( const bytes &secKey )
	{
		try
		{
			SetIV( secKey );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool Decrypt( const bytes &encrypted, bytes &decrypted )
	{
		try
		{
			CheckKey( );
			decrypted.resize( encrypted.size( ) );
			decrypter.ProcessData( decrypted.data( ), encrypted.data( ), encrypted.size( ) );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool Encrypt( const bytes &decrypted, bytes &encrypted )
	{
		try
		{
			CheckKey( );
			encrypted.resize( decrypted.size( ) );
			encrypter.ProcessData( encrypted.data( ), decrypted.data( ), decrypted.size( ) );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	const std::string &GetLastError( ) const
	{
		return lasterror;
	}

private:
	void CheckKey( ) const
	{
		if( !keyset )
			throw CryptoPP::Exception( CryptoPP::Exception::OTHER_ERROR, "AES key was not set" );
	}

	void SetKey( const bytes &priKey )
	{
		decrypter.SetKey( priKey.data( ), priKey.size( ) );
		encrypter.SetKey( priKey.data( ), priKey.size( ) );
		keyset = true;
	}

	void SetIV( const bytes &secKey )
	{
		decrypter.Resynchronize( secKey.data( ), secKey.size( ) );
		encrypter.Resynchronize( secKey.data( ), secKey.size( ) );
	}

	bool keyset;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption decrypter;
	CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption encrypter;
	std::string lasterror;
};

class RSA : public Crypter
{
public:
	RSA( ) :
		prikeyset( false ),
		pubkeyset( false )
	{ }

	std::string AlgorithmName( ) const
	{
		return encrypter.AlgorithmName( );
	}

	size_t MaxPlaintextLength( size_t length ) const
	{
		return encrypter.MaxPlaintextLength( length );
	}

	size_t CiphertextLength( size_t length ) const
	{
		return encrypter.CiphertextLength( length );
	}

	size_t FixedMaxPlaintextLength( ) const
	{
		return encrypter.FixedMaxPlaintextLength( );
	}

	size_t FixedCiphertextLength( ) const
	{
		return encrypter.FixedCiphertextLength( );
	}

	size_t GetValidPrimaryKeyLength( size_t length ) const
	{
		return length;
	}

	bool GeneratePrimaryKey( uint32_t priSize, bytes &priKey, bool use )
	{
		try
		{
			CryptoPP::RSA::PrivateKey privKey;

			CryptoPP::AutoSeededRandomPool prng;
			privKey.GenerateRandomWithKeySize( prng, priSize );

			bytes_string priStr;
			bytes_sink privSink( priStr );
			privKey.Save( privSink.Ref( ) );
			priKey.assign( priStr.begin( ), priStr.end( ) );

			if( use )
				SetPrivateKey( privKey );

			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool SetPrimaryKey( const bytes &priKey )
	{
		try
		{
			CryptoPP::RSA::PrivateKey privKey;
			CryptoPP::StringSource stringSource( priKey.data( ), priKey.size( ), true );
			privKey.Load( stringSource.Ref( ) );
			SetPrivateKey( privKey );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	size_t GetValidSecondaryKeyLength( size_t length ) const
	{
		return length;
	}

	bool GenerateSecondaryKey(
		const bytes &priKey,
		size_t,
		bytes &secKey,
		bool use
	)
	{
		try
		{
			CryptoPP::RSA::PrivateKey privKey;

			CryptoPP::StringSource stringSource( priKey.data( ), priKey.size( ), true );
			privKey.Load( stringSource.Ref( ) );

			CryptoPP::RSA::PublicKey pubKey;
			pubKey.AssignFrom( privKey );

			bytes_string secStr;
			bytes_sink pubSink( secStr );
			pubKey.Save( pubSink.Ref( ) );
			secKey.assign( secStr.begin( ), secStr.end( ) );

			if( use )
				SetPublicKey( pubKey );

			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool SetSecondaryKey( const bytes &secKey )
	{
		try
		{
			CryptoPP::RSA::PublicKey pubKey;
			CryptoPP::StringSource stringSource( secKey.data( ), secKey.size( ), true );
			pubKey.Load( stringSource.Ref( ) );
			SetPublicKey( pubKey );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool Decrypt( const bytes &encrypted, bytes &decrypted )
	{
		try
		{
			CheckPrivateKey( );
			CryptoPP::AutoSeededRandomPool prng;
			decrypted.resize( decrypter.MaxPlaintextLength( encrypted.size( ) ) );
			CryptoPP::DecodingResult res = decrypter.Decrypt(
				prng,
				encrypted.data( ),
				encrypted.size( ),
				decrypted.data( )
			);
			decrypted.resize( res.messageLength );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool Encrypt( const bytes &decrypted, bytes &encrypted )
	{
		try
		{
			CheckPublicKey( );
			CryptoPP::AutoSeededRandomPool prng;
			encrypted.resize( encrypter.CiphertextLength( decrypted.size( ) ) );
			encrypter.Encrypt( prng, decrypted.data( ), decrypted.size( ), encrypted.data( ) );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	const std::string &GetLastError( ) const
	{
		return lasterror;
	}

private:
	void CheckPrivateKey( ) const
	{
		if( !prikeyset )
			throw CryptoPP::Exception( CryptoPP::Exception::OTHER_ERROR, "RSA private key was not set" );
	}

	void SetPrivateKey( const CryptoPP::RSA::PrivateKey &privKey )
	{
		decrypter.AccessKey( ).AssignFrom( privKey );
		prikeyset = true;
	}

	void CheckPublicKey( ) const
	{
		if( !pubkeyset )
			throw CryptoPP::Exception( CryptoPP::Exception::OTHER_ERROR, "RSA public key was not set" );
	}

	void SetPublicKey( const CryptoPP::RSA::PublicKey &pubKey )
	{
		encrypter.AccessKey( ).AssignFrom( pubKey );
		pubkeyset = true;
	}

	bool prikeyset;
	bool pubkeyset;
	CryptoPP::RSAES_OAEP_SHA_Decryptor decrypter;
	CryptoPP::RSAES_OAEP_SHA_Encryptor encrypter;
	std::string lasterror;
};

class ECP : public Crypter
{
public:
	ECP( ) :
		prikeyset( false ),
		pubkeyset( false )
	{ }

	std::string AlgorithmName( ) const
	{
		return encrypter.AlgorithmName( );
	}

	size_t MaxPlaintextLength( size_t length ) const
	{
		return encrypter.MaxPlaintextLength( length );
	}

	size_t CiphertextLength( size_t length ) const
	{
		return encrypter.CiphertextLength( length );
	}

	size_t FixedMaxPlaintextLength( ) const
	{
		return encrypter.FixedMaxPlaintextLength( );
	}

	size_t FixedCiphertextLength( ) const
	{
		return encrypter.FixedCiphertextLength( );
	}

	size_t GetValidPrimaryKeyLength( size_t length ) const
	{
		return length;
	}

	bool GeneratePrimaryKey( size_t priSize, bytes &priKey, bool use )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;

			CryptoPP::AutoSeededRandomPool prng;
			privKey.GenerateRandomWithKeySize( prng, priSize );

			bytes_string priStr;
			bytes_sink privSink( priStr );
			privKey.Save( privSink.Ref( ) );
			priKey.assign( priStr.begin( ), priStr.end( ) );

			if( use )
				SetPrivateKey( privKey );

			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool SetPrimaryKey( const bytes &priKey )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
			CryptoPP::StringSource stringSource( priKey.data( ), priKey.size( ), true );
			privKey.Load( stringSource.Ref( ) );
			SetPrivateKey( privKey );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	size_t GetValidSecondaryKeyLength( size_t length ) const
	{
		return length;
	}

	bool GenerateSecondaryKey( const bytes &priKey, size_t, bytes &secKey, bool use )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
			CryptoPP::StringSource stringSource( priKey.data( ), priKey.size( ), true );
			privKey.Load( stringSource.Ref( ) );

			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
			pubKey.AssignFrom( privKey );

			bytes_string secStr;
			bytes_sink pubSink( secStr );
			pubKey.Save( pubSink.Ref( ) );
			secKey.assign( secStr.begin( ), secStr.end( ) );

			if( use )
				SetPublicKey( pubKey );

			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool SetSecondaryKey( const bytes &secKey )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
			CryptoPP::StringSource stringSource( secKey.data( ), secKey.size( ), true );
			pubKey.Load( stringSource.Ref( ) );
			SetPublicKey( pubKey );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool Decrypt( const bytes &encrypted, bytes &decrypted )
	{
		try
		{
			CheckPrivateKey( );
			CryptoPP::AutoSeededRandomPool prng;
			decrypted.resize( decrypter.MaxPlaintextLength( encrypted.size( ) ) );
			CryptoPP::DecodingResult res = decrypter.Decrypt(
				prng,
				encrypted.data( ),
				encrypted.size( ),
				decrypted.data( )
			);
			decrypted.resize( res.messageLength );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	bool Encrypt( const bytes &decrypted, bytes &encrypted )
	{
		try
		{
			CheckPublicKey( );
			CryptoPP::AutoSeededRandomPool prng;
			encrypted.resize( encrypter.CiphertextLength( decrypted.size( ) ) );
			encrypter.Encrypt( prng, decrypted.data( ), decrypted.size( ), encrypted.data( ) );
			return true;
		}
		catch( CryptoPP::Exception &e )
		{
			lasterror = e.GetWhat( );
		}

		return false;
	}

	const std::string &GetLastError( ) const
	{
		return lasterror;
	}

private:
	void CheckPrivateKey( ) const
	{
		if( !prikeyset )
			throw CryptoPP::Exception( CryptoPP::Exception::OTHER_ERROR, "ECP private key was not set" );
	}

	void SetPrivateKey( const CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey &privKey )
	{
		decrypter.AccessKey( ).AssignFrom( privKey );
		prikeyset = true;
	}

	void CheckPublicKey( ) const
	{
		if( !pubkeyset )
			throw CryptoPP::Exception( CryptoPP::Exception::OTHER_ERROR, "ECP public key was not set" );
	}

	void SetPublicKey( const CryptoPP::ECIES<CryptoPP::ECP>::PublicKey &pubKey )
	{
		encrypter.AccessKey( ).AssignFrom( pubKey );
		pubkeyset = true;
	}

	bool prikeyset;
	bool pubkeyset;
	CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decrypter;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encrypter;
	std::string lasterror;
};

static const char *metaname = "crypter";
static int32_t metatype = GarrysMod::Lua::Type::NONE;
static const char *invalid_error = "invalid crypter";

inline void CheckType( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	if( !LUA->IsType( index, metatype ) )
		luaL_typerror( LUA->GetState(), index, metaname );
}

static Crypter *GetUserData( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	CheckType( LUA, index );
	return  LUA->GetUserType<Crypter>( index, metatype );
}

static Crypter *Get( GarrysMod::Lua::ILuaBase *LUA, int32_t index )
{
	Crypter *crypter = GetUserData( LUA, index );
	if( crypter == nullptr )
		LUA->ArgError( index, invalid_error );

	return crypter;
}

LUA_FUNCTION_STATIC( tostring )
{

#if defined _WIN32

	lua_pushfstring( LUA->GetState(), "%s: %p", metaname, Get( LUA, 1 ) );

#elif defined __linux || defined __APPLE__

	lua_pushfstring( LUA->GetState(), "%s: 0x%p", metaname, Get( LUA, 1 ) );

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

	lua_getfenv( LUA->GetState(), 1 );
	LUA->Push( 2 );
	LUA->RawGet( -2 );
	return 1;
}

LUA_FUNCTION_STATIC( newindex )
{
	CheckType( LUA, 1 );

	lua_getfenv( LUA->GetState(), 1 );
	LUA->Push( 2 );
	LUA->Push( 3 );
	LUA->RawSet( -3 );
	return 0;
}

LUA_FUNCTION_STATIC( gc )
{
	Crypter *crypter = GetUserData( LUA, 1 );
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
	Crypter *crypter = Get( LUA, 1 );
	size_t keySize = static_cast<size_t>( LUA->CheckNumber( 2 ) );

	bool use = true;
	if( LUA->Top( ) > 2 )
	{
		LUA->CheckType( 3, GarrysMod::Lua::Type::BOOL );
		use = LUA->GetBool( 3 );
	}

	bytes priKey;
	if( !crypter->GeneratePrimaryKey( keySize, priKey, use ) )
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
	Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t priLen = 0;
	const uint8_t *priKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &priLen ) );

	bytes privKey( priKey, priKey + priLen );
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
	Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );
	size_t keySize = static_cast<size_t>( LUA->CheckNumber( 3 ) );

	size_t priLen = 0;
	const uint8_t *priKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &priLen ) );

	bool use = true;
	if( LUA->Top( ) > 3 )
	{
		LUA->CheckType( 4, GarrysMod::Lua::Type::BOOL );
		use = LUA->GetBool( 4 );
	}

	bytes privKey( priKey, priKey + priLen );
	bytes secKey;
	if( !crypter->GenerateSecondaryKey( privKey, keySize, secKey, use ) )
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
	Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t secLen = 0;
	const uint8_t *secKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &secLen ) );

	bytes secoKey( secKey, secKey + secLen );
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
	Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	bytes encrypted( data, data + len );
	bytes decrypted;
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
	Crypter *crypter = Get( LUA, 1 );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	bytes decrypted( data, data + len );
	bytes encrypted;
	if( !crypter->Encrypt( decrypted, encrypted ) )
	{
		LUA->PushNil( );
		LUA->PushString( crypter->GetLastError( ).c_str( ) );
		return 2;
	}

	LUA->PushString( reinterpret_cast<const char *>( encrypted.data( ) ), encrypted.size( ) );
	return 1;
}

template<typename Crypter, bool Secure = true>
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

	LUA->PushCFunction( Creator<AES> );
	LUA->SetField( -2, "AES" );

	LUA->PushCFunction( Creator<RSA> );
	LUA->SetField( -2, "RSA" );

	LUA->PushCFunction( Creator<ECP> );
	LUA->SetField( -2, "ECP" );
}

void Deinitialize( GarrysMod::Lua::ILuaBase *LUA )
{
	LUA->PushNil( );
	LUA->SetField( GarrysMod::Lua::INDEX_REGISTRY, metaname );
}

}
