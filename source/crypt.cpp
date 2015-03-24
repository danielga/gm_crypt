#include <GarrysMod/Lua/Interface.h>
#include <cryptopp/crc.h>
#include <cryptopp/sha.h>
#include <cryptopp/tiger.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/whrlpool.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <stdint.h>
#include <stdio.h>
#include <symbolfinder.hpp>
#include <vector>

#define THROW_ERROR( error ) ( LUA->ThrowError( error ), 0 )
#define LUA_ERROR( ) THROW_ERROR( LUA->GetString( ) )

#define HASHER_METATABLE "Hasher"
#define HASHER_TYPE 30

#define GET_USERDATA( index ) reinterpret_cast<GarrysMod::Lua::UserData *>( LUA->GetUserdata( index ) )
#define GET_HASHER( index ) reinterpret_cast<CryptoPP::HashTransformation *>( GET_USERDATA( index )->data )
#define VALIDATE_HASHER( hasher ) if( hasher == 0 ) return THROW_ERROR( HASHER_METATABLE " object is not valid" )

#if defined _WIN32

#define snprintf _snprintf

#endif

typedef void ( *lua_getfenv_t )( lua_State *L, int index );
lua_getfenv_t lua_getfenv = 0;

typedef int ( *lua_setfenv_t )( lua_State *L, int index );
lua_setfenv_t lua_setfenv = 0;

class BaseObject
{
public:
	virtual void SetPrimaryKey( const std::string &priKey ) = 0;
	virtual std::string GenerateSecondaryKey( const std::string &priKey ) = 0;
	virtual void SetSecondaryKey( const std::string &secKey ) = 0;
	virtual std::string Decrypt( const std::string &data ) = 0;
	virtual std::string Encrypt( const std::string &data ) = 0;
};

class AESObject : public BaseObject
{
public:
	void SetPrimaryKey( const std::string &priKey )
	{
		size_t keySize = priKey.size( );
		if( keySize != 16 && keySize != 24 && keySize != 32 )
			return;

		const uint8_t *keyData = reinterpret_cast<const uint8_t *>( priKey.c_str( ) );

		decryptor.SetKey( keyData, keySize );
		encryptor.SetKey( keyData, keySize );
	}

	std::string GenerateSecondaryKey( const std::string &priKey )
	{
		return std::string( );
	}

	void SetSecondaryKey( const std::string &secKey )
	{
		size_t ivSize = secKey.size( );
		if( ivSize != 16 && ivSize != 24 && ivSize != 32 )
			return;

		const uint8_t *ivData = reinterpret_cast<const uint8_t *>( secKey.c_str( ) );

		decryptor.Resynchronize( ivData, ivSize );
		encryptor.Resynchronize( ivData, ivSize );
	}

	std::string Decrypt( const std::string &data )
	{
		std::string decrypted;
		CryptoPP::StringSource(
			data, true,
			new CryptoPP::StreamTransformationFilter(
				decryptor,
				new CryptoPP::StringSink( decrypted )
			)
		);

		return decrypted;
	}

	std::string Encrypt( const std::string &data )
	{
		std::string encrypted;
		CryptoPP::StringSource(
			data, true,
			new CryptoPP::StreamTransformationFilter(
				encryptor,
				new CryptoPP::StringSink( encrypted )
			)
		);

		return encrypted;
	}

private:
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
};

class RSAObject : public BaseObject
{
public:
	void SetPrimaryKey( const std::string &priKey )
	{
		CryptoPP::RSA::PublicKey privKey;
		CryptoPP::StringSource stringSource( priKey, true );
		privKey.Load( stringSource.Ref( ) );
		decryptor.AccessKey( ).AssignFrom( privKey );
	}

	std::string GenerateSecondaryKey( const std::string &priKey )
	{
		CryptoPP::RSA::PublicKey privKey;
		CryptoPP::StringSource stringSource( priKey, true );
		privKey.Load( stringSource.Ref( ) );

		CryptoPP::RSA::PublicKey pubKey;
		pubKey.AssignFrom( privKey );
		std::string publicKey;
		CryptoPP::StringSink pubSink( publicKey );
		pubKey.Save( pubSink.Ref( ) );
		return publicKey;
	}

	void SetSecondaryKey( const std::string &secKey )
	{
		CryptoPP::RSA::PublicKey pubKey;
		CryptoPP::StringSource stringSource( secKey, true );
		pubKey.Load( stringSource.Ref( ) );
		encryptor.AccessKey( ).AssignFrom( pubKey );
	}

	std::string Decrypt( const std::string &data )
	{
		CryptoPP::AutoSeededRandomPool rng;
		std::string decrypted;
		CryptoPP::StringSource(
			data, true,
			new CryptoPP::PK_DecryptorFilter(
				rng, decryptor,
				new CryptoPP::StringSink( decrypted )
			)
		);

		return decrypted;
	}

	std::string Encrypt( const std::string &data )
	{
		CryptoPP::AutoSeededRandomPool rng;
		std::string encrypted;
		CryptoPP::StringSource(
			data, true,
			new CryptoPP::PK_EncryptorFilter(
				rng, encryptor,
				new CryptoPP::StringSink( encrypted )
			)
		);

		return encrypted;
	}

private:
	CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor;
	CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor;
};

class ECCObject : public BaseObject
{
public:
	void SetPrimaryKey( const std::string &priKey )
	{
		CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
		CryptoPP::StringSource stringSource( priKey, true );
		privKey.Load( stringSource.Ref( ) );
		decryptor.AccessKey( ).AssignFrom( privKey );
	}

	std::string GenerateSecondaryKey( const std::string &priKey )
	{
		CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
		CryptoPP::StringSource stringSource( priKey, true );
		privKey.Load( stringSource.Ref( ) );

		CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
		pubKey.AssignFrom( privKey );
		std::string publicKey;
		CryptoPP::StringSink pubSink( publicKey );
		pubKey.Save( pubSink.Ref( ) );
		return publicKey;
	}

	void SetSecondaryKey( const std::string &secKey )
	{
		CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
		CryptoPP::StringSource stringSource( secKey, true );
		pubKey.Load( stringSource.Ref( ) );
		encryptor.AccessKey( ).AssignFrom( pubKey );
	}

	std::string Decrypt( const std::string &data )
	{
		CryptoPP::AutoSeededRandomPool rng;
		std::string decrypted;
		CryptoPP::StringSource(
			data, true,
			new CryptoPP::PK_DecryptorFilter(
				rng, decryptor,
				new CryptoPP::StringSink( decrypted )
			)
		);

		return decrypted;
	}

	std::string Encrypt( const std::string &data )
	{
		CryptoPP::AutoSeededRandomPool rng;
		std::string encrypted;
		CryptoPP::StringSource(
			data, true,
			new CryptoPP::PK_EncryptorFilter(
				rng, encryptor,
				new CryptoPP::StringSink( encrypted )
			)
		);

		return encrypted;
	}

private:
	CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decryptor;
	CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encryptor;
};

LUA_FUNCTION_STATIC( aesEncrypt )
{
	bool hasIV = LUA->Top( ) > 2;

	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );
	if( hasIV )
		LUA->CheckType( 3, GarrysMod::Lua::Type::STRING );

	size_t keyLen = 0;
	const uint8_t *key = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &keyLen ) );
	if( keyLen != 16 && keyLen != 24 && keyLen != 32 )
		return THROW_ERROR( "invalid key length supplied" );

	size_t ivLen = 0;
	const uint8_t *iv = NULL;
	if( hasIV )
	{
		iv = reinterpret_cast<const uint8_t *>( LUA->GetString( 3, &ivLen ) );
		if( ivLen != 16 && ivLen != 24 && ivLen != 32 )
			return THROW_ERROR( "invalid IV length supplied" );
	}

	size_t dataLength = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 1, &dataLength ) );

	try
	{
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
		if( hasIV )
			encryptor.SetKeyWithIV( key, keyLen, iv, ivLen );
		else
			encryptor.SetKey( key, keyLen );

		std::string encrypted;
		CryptoPP::StringSource(
			data, dataLength, true,
			new CryptoPP::StreamTransformationFilter(
				encryptor,
				new CryptoPP::StringSink( encrypted )
			)
		);

		LUA->PushString( encrypted.c_str( ), encrypted.size( ) );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( aesDecrypt )
{
	bool hasIV = LUA->Top( ) > 2;

	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );
	if( hasIV )
		LUA->CheckType( 3, GarrysMod::Lua::Type::STRING );

	size_t keyLen = 0;
	const uint8_t *key = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &keyLen ) );
	if( keyLen != 16 && keyLen != 24 && keyLen != 32 )
		return THROW_ERROR( "invalid key length supplied" );

	size_t ivLen = 0;
	const uint8_t *iv = NULL;
	if( hasIV )
	{
		iv = reinterpret_cast<const uint8_t *>( LUA->GetString( 3, &ivLen ) );
		if( ivLen != 16 && ivLen != 24 && ivLen != 32 )
			return THROW_ERROR( "invalid IV length supplied" );
	}

	size_t dataLength = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 1, &dataLength ) );

	try
	{
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
		if( hasIV )
			decryptor.SetKeyWithIV( key, keyLen, iv, ivLen );
		else
			decryptor.SetKey( key, keyLen );

		std::string decrypted;
		CryptoPP::StringSource(
			data, dataLength, true,
			new CryptoPP::StreamTransformationFilter(
				decryptor,
				new CryptoPP::StringSink( decrypted )
			)
		);

		LUA->PushString( decrypted.c_str( ), decrypted.size( ) );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( rsaGeneratePublicKey )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );

	size_t privateKeyLen = 0;
	const uint8_t *privateKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 1, &privateKeyLen ) );

	try
	{
		CryptoPP::RSA::PrivateKey privKey;
		CryptoPP::ByteQueue queue;
		queue.Put( privateKey, privateKeyLen );
		queue.MessageEnd( );
		privKey.Load( queue.Ref( ) );

		CryptoPP::RSA::PublicKey pubKey;
		pubKey.AssignFrom( privKey );
		std::string publicKey;
		CryptoPP::StringSink pubSink( publicKey );
		pubKey.Save( pubSink.Ref( ) );

		LUA->PushString( publicKey.c_str( ), publicKey.size( ) );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( rsaEncrypt )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t dataLength = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 1, &dataLength ) );

	size_t publicKeyLen = 0;
	const uint8_t *publicKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &publicKeyLen ) );

	try
	{
		CryptoPP::RSA::PublicKey pubKey;
		CryptoPP::ByteQueue queue;
		queue.Put( publicKey, publicKeyLen );
		queue.MessageEnd( );
		pubKey.Load( queue.Ref( ) );

		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::RSAES_OAEP_SHA_Encryptor enc( pubKey );
		std::string encrypted;
		CryptoPP::StringSource(
			data, dataLength, true,
			new CryptoPP::PK_EncryptorFilter(
				rng, enc,
				new CryptoPP::StringSink( encrypted )
			)
		);

		LUA->PushString( encrypted.c_str( ), encrypted.size( ) );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( rsaDecrypt )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t dataLength = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 1, &dataLength ) );

	size_t privateKeyLen = 0;
	const uint8_t *privateKey = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &privateKeyLen ) );

	try
	{
		CryptoPP::RSA::PrivateKey privKey;
		CryptoPP::ByteQueue queue;
		queue.Put( privateKey, privateKeyLen );
		queue.MessageEnd( );
		privKey.Load( queue.Ref( ) );

		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::RSAES_OAEP_SHA_Decryptor dec( privKey );
		std::string decrypted;
		CryptoPP::StringSource(
			data, dataLength, true,
			new CryptoPP::PK_DecryptorFilter(
				rng, dec,
				new CryptoPP::StringSink( decrypted )
			)
		);

		LUA->PushString( decrypted.c_str( ), decrypted.size( ) );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( hasher__tostring )
{
	LUA->CheckType( 1, HASHER_TYPE );

	GarrysMod::Lua::UserData *userdata = GET_USERDATA( 1 );
	char buffer[30];
	snprintf( buffer, sizeof( buffer ), "%s: 0x%p", HASHER_METATABLE, userdata->data );
	LUA->PushString( buffer );
	return 1;
}

LUA_FUNCTION_STATIC( hasher__eq )
{
	LUA->CheckType( 1, HASHER_TYPE );
	LUA->CheckType( 2, HASHER_TYPE );

	LUA->PushBool( GET_USERDATA( 1 )->data == GET_USERDATA( 2 )->data );
	return 1;
}

LUA_FUNCTION_STATIC( hasher__index )
{
	LUA->CheckType( 1, HASHER_TYPE );

	LUA->CreateMetaTableType( HASHER_METATABLE, HASHER_TYPE );
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

LUA_FUNCTION_STATIC( hasher__newindex )
{
	LUA->CheckType( 1, HASHER_TYPE );

	lua_getfenv( state, 1 );
	LUA->Push( 2 );
	LUA->Push( 3 );
	LUA->RawSet( -3 );
	return 0;
}

LUA_FUNCTION_STATIC( hasher__gc )
{
	LUA->CheckType( 1, HASHER_TYPE );

	GarrysMod::Lua::UserData *userdata = GET_USERDATA( 1 );
	CryptoPP::HashTransformation *hasher = reinterpret_cast<CryptoPP::HashTransformation *>( userdata->data );
	VALIDATE_HASHER( hasher );

	userdata->data = 0;

	try
	{
		delete hasher;
		return 0;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( hasher_update )
{
	LUA->CheckType( 1, HASHER_TYPE );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	CryptoPP::HashTransformation *hasher = GET_HASHER( 1 );
	VALIDATE_HASHER( hasher );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	try
	{
		hasher->Update( data, len );
		return 0;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( hasher_final )
{
	LUA->CheckType( 1, HASHER_TYPE );

	CryptoPP::HashTransformation *hasher = GET_HASHER( 1 );
	VALIDATE_HASHER( hasher );

	try
	{
		uint32_t size = hasher->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = &digest[0];

		hasher->Final( digestptr );

		LUA->PushString( reinterpret_cast<const char *>( digestptr ), size );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( hasher_restart )
{
	LUA->CheckType( 1, HASHER_TYPE );

	CryptoPP::HashTransformation *hasher = GET_HASHER( 1 );
	VALIDATE_HASHER( hasher );

	try
	{
		hasher->Restart( );
		return 0;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( hasher_digest )
{
	LUA->CheckType( 1, HASHER_TYPE );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	CryptoPP::HashTransformation *hasher = GET_HASHER( 1 );
	VALIDATE_HASHER( hasher );

	uint32_t len = 0;
	const uint8_t *data = reinterpret_cast<const uint8_t *>( LUA->GetString( 2, &len ) );

	try
	{
		uint32_t size = hasher->DigestSize( );
		std::vector<uint8_t> digest( size );
		uint8_t *digestptr = &digest[0];

		hasher->CalculateDigest( digestptr, data, len );

		LUA->PushString( reinterpret_cast<const char *>( digestptr ), size );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION_STATIC( hasher_name )
{
	LUA->CheckType( 1, HASHER_TYPE );

	CryptoPP::HashTransformation *hasher = GET_HASHER( 1 );
	VALIDATE_HASHER( hasher );

	LUA->PushString( hasher->AlgorithmName( ).c_str( ) );
	return 1;
}

LUA_FUNCTION_STATIC( hasher_size )
{
	LUA->CheckType( 1, HASHER_TYPE );

	CryptoPP::HashTransformation *hasher = GET_HASHER( 1 );
	VALIDATE_HASHER( hasher );

	LUA->PushNumber( hasher->DigestSize( ) );
	return 1;
}

LUA_FUNCTION_STATIC( hasher_blocksize )
{
	LUA->CheckType( 1, HASHER_TYPE );

	CryptoPP::HashTransformation *hasher = GET_HASHER( 1 );
	VALIDATE_HASHER( hasher );

	LUA->PushNumber( hasher->OptimalBlockSize( ) );
	return 1;
}

#define AddFunction( name, func )	\
	LUA->PushCFunction( func );		\
	LUA->SetField( -2, name );

#define AddHashFunction( name, hashType )		\
	LUA->PushCFunction( hash_ ## hashType );	\
	LUA->SetField( -2, name );

#define HashFunction( hashType )																	\
LUA_FUNCTION_STATIC( hash_ ## hashType )															\
{																									\
	void *luadata = LUA->NewUserdata( sizeof( GarrysMod::Lua::UserData ) );							\
	GarrysMod::Lua::UserData *userdata = reinterpret_cast<GarrysMod::Lua::UserData *>( luadata );	\
	userdata->data = new CryptoPP::hashType( );														\
	userdata->type = HASHER_TYPE;																	\
																									\
	LUA->CreateMetaTableType( HASHER_METATABLE, HASHER_TYPE );										\
	LUA->SetMetaTable( -2 );																		\
																									\
	LUA->CreateTable( );																			\
	lua_setfenv( state, -2 );																		\
																									\
	return 1;																						\
}

HashFunction( CRC32 );

HashFunction( SHA1 );
HashFunction( SHA224 );
HashFunction( SHA256 );
HashFunction( SHA384 );
HashFunction( SHA512 );

HashFunction( Tiger );

HashFunction( Whirlpool );

HashFunction( MD2 );
HashFunction( MD4 );
HashFunction( MD5 );

HashFunction( RIPEMD128 );
HashFunction( RIPEMD160 );
HashFunction( RIPEMD256 );
HashFunction( RIPEMD320 );

GMOD_MODULE_OPEN( )
{
	SymbolFinder symfinder;

#if defined _WIN32

	lua_getfenv = reinterpret_cast<lua_getfenv_t>( symfinder.FindSymbolFromBinary( "lua_shared.dll", "lua_getfenv" ) );
	lua_setfenv = reinterpret_cast<lua_setfenv_t>( symfinder.FindSymbolFromBinary( "lua_shared.dll", "lua_setfenv" ) );

#elif defined __linux

	lua_getfenv = reinterpret_cast<lua_getfenv_t>( symfinder.FindSymbolFromBinary( "garrysmod/bin/lua_shared_srv.so", "lua_getfenv" ) );
	lua_setfenv = reinterpret_cast<lua_setfenv_t>( symfinder.FindSymbolFromBinary( "garrysmod/bin/lua_shared_srv.so", "lua_setfenv" ) );

#elif defined __APPLE__

	lua_getfenv = reinterpret_cast<lua_getfenv_t>( symfinder.FindSymbolFromBinary( "garrysmod/bin/lua_shared.dylib", "_lua_getfenv" ) );
	lua_setfenv = reinterpret_cast<lua_setfenv_t>( symfinder.FindSymbolFromBinary( "garrysmod/bin/lua_shared.dylib", "_lua_setfenv" ) );

#endif

	LUA->CreateMetaTableType( HASHER_METATABLE, HASHER_TYPE );

	LUA->Push( -1 );
	LUA->SetField( -2, "__metatable" );

	AddFunction( "__tostring", hasher__tostring );
	AddFunction( "__eq", hasher__eq );
	AddFunction( "__index", hasher__index );
	AddFunction( "__newindex", hasher__newindex );
	AddFunction( "__gc", hasher__gc );

	AddFunction( "Update", hasher_update );
	AddFunction( "Final", hasher_final );
	AddFunction( "Restart", hasher_restart );

	AddFunction( "CalculateDigest", hasher_digest );

	AddFunction( "AlgorythmName", hasher_name );
	AddFunction( "DigestSize", hasher_size );
	AddFunction( "OptimalBlockSize", hasher_blocksize );



	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->CreateTable( );

	AddHashFunction( "crc32", CRC32 );

	AddHashFunction( "sha1", SHA1 );
	AddHashFunction( "sha224", SHA224 );
	AddHashFunction( "sha256", SHA256 );
	AddHashFunction( "sha384", SHA384 );
	AddHashFunction( "sha512", SHA512 );

	AddHashFunction( "tiger", Tiger );

	AddHashFunction( "whirlpool", Whirlpool );

	AddHashFunction( "md2", MD2 );
	AddHashFunction( "md4", MD4 );
	AddHashFunction( "md5", MD5 );

	AddHashFunction( "ripemd128", RIPEMD128 );
	AddHashFunction( "ripemd160", RIPEMD160 );
	AddHashFunction( "ripemd256", RIPEMD256 );
	AddHashFunction( "ripemd320", RIPEMD320 );

	AddFunction( "aesEncrypt", aesEncrypt );
	AddFunction( "aesDecrypt", aesDecrypt );

	AddFunction( "rsaGeneratePublicKey", rsaGeneratePublicKey );
	AddFunction( "rsaEncrypt", rsaEncrypt );
	AddFunction( "rsaDecrypt", rsaDecrypt );

	LUA->SetField( -2, "crypt" );

	return 0;
}

GMOD_MODULE_CLOSE( )
{
	return 0;
}