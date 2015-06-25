#include <GarrysMod/Lua/Interface.h>
#include <lua.hpp>
#include <cstdint>
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
#include <string>
#include <vector>

namespace crypt
{

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
		LUA->ThrowError( "invalid key length supplied" );

	size_t ivLen = 0;
	const uint8_t *iv = NULL;
	if( hasIV )
	{
		iv = reinterpret_cast<const uint8_t *>( LUA->GetString( 3, &ivLen ) );
		if( ivLen != 16 && ivLen != 24 && ivLen != 32 )
			LUA->ThrowError( "invalid IV length supplied" );
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

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
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
		LUA->ThrowError( "invalid key length supplied" );

	size_t ivLen = 0;
	const uint8_t *iv = NULL;
	if( hasIV )
	{
		iv = reinterpret_cast<const uint8_t *>( LUA->GetString( 3, &ivLen ) );
		if( ivLen != 16 && ivLen != 24 && ivLen != 32 )
			LUA->ThrowError( "invalid IV length supplied" );
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

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
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

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
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

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
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

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
}

static void Initialize( lua_State *state )
{
	LUA->PushCFunction( aesEncrypt );
	LUA->SetField( -2, "aesEncrypt" );

	LUA->PushCFunction( aesDecrypt );
	LUA->SetField( -2, "aesDecrypt" );

	LUA->PushCFunction( rsaGeneratePublicKey );
	LUA->SetField( -2, "rsaGeneratePublicKey" );

	LUA->PushCFunction( rsaEncrypt );
	LUA->SetField( -2, "rsaEncrypt" );

	LUA->PushCFunction( rsaDecrypt );
	LUA->SetField( -2, "rsaDecrypt" );
}

}

namespace hasher
{

struct UserData
{
	CryptoPP::HashTransformation *data;
	uint8_t type;
};

static const char *metaname = "Hasher";
static const uint8_t metatype = 30;
static const char *tablename = "crypt";
static const char *invalid_error = "Hasher object is not valid";

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
	lua_pushfstring( state, "%s: 0x%p", metaname, Get( state, 1 ) );
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
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
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
		return 0;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
}

LUA_FUNCTION_STATIC( Final )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );

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

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
}

LUA_FUNCTION_STATIC( Restart )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );

	try
	{
		hasher->Restart( );
		return 0;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
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
		uint8_t *digestptr = &digest[0];

		hasher->CalculateDigest( digestptr, data, len );

		LUA->PushString( reinterpret_cast<const char *>( digestptr ), size );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	LUA->ThrowError( LUA->GetString( -1 ) );
	return 0;
}

LUA_FUNCTION_STATIC( Name )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );
	LUA->PushString( hasher->AlgorithmName( ).c_str( ) );
	return 1;
}

LUA_FUNCTION_STATIC( Size )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );
	LUA->PushNumber( hasher->DigestSize( ) );
	return 1;
}

LUA_FUNCTION_STATIC( BlockSize )
{
	CryptoPP::HashTransformation *hasher = Get( state, 1 );
	LUA->PushNumber( hasher->OptimalBlockSize( ) );
	return 1;
}

template<typename Hasher>
LUA_FUNCTION_STATIC( Function )
{
	void *luadata = LUA->NewUserdata( sizeof( UserData ) );
	UserData *userdata = reinterpret_cast<UserData *>( luadata );
	userdata->data = new Hasher( );
	userdata->type = metatype;

	LUA->CreateMetaTableType( metaname, metatype );
	LUA->SetMetaTable( -2 );

	LUA->CreateTable( );
	lua_setfenv( state, -2 );

	return 1;
}

static void Initialize( lua_State *state )
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

	LUA->PushCFunction( Function<CryptoPP::CRC32> );
	LUA->SetField( -2, "crc32" );

	LUA->PushCFunction( Function<CryptoPP::SHA1> );
	LUA->SetField( -2, "sha1" );

	LUA->PushCFunction( Function<CryptoPP::SHA224> );
	LUA->SetField( -2, "sha224" );

	LUA->PushCFunction( Function<CryptoPP::SHA256> );
	LUA->SetField( -2, "sha256" );

	LUA->PushCFunction( Function<CryptoPP::SHA384> );
	LUA->SetField( -2, "sha384" );

	LUA->PushCFunction( Function<CryptoPP::SHA512> );
	LUA->SetField( -2, "sha512" );

	LUA->PushCFunction( Function<CryptoPP::Tiger> );
	LUA->SetField( -2, "tiger" );

	LUA->PushCFunction( Function<CryptoPP::Whirlpool> );
	LUA->SetField( -2, "whirlpool" );

	LUA->PushCFunction( Function<CryptoPP::Weak::MD2> );
	LUA->SetField( -2, "md2" );

	LUA->PushCFunction( Function<CryptoPP::Weak::MD4> );
	LUA->SetField( -2, "md4" );

	LUA->PushCFunction( Function<CryptoPP::Weak::MD5> );
	LUA->SetField( -2, "md5" );

	LUA->PushCFunction( Function<CryptoPP::RIPEMD128> );
	LUA->SetField( -2, "ripemd128" );

	LUA->PushCFunction( Function<CryptoPP::RIPEMD160> );
	LUA->SetField( -2, "ripemd160" );

	LUA->PushCFunction( Function<CryptoPP::RIPEMD256> );
	LUA->SetField( -2, "ripemd256" );

	LUA->PushCFunction( Function<CryptoPP::RIPEMD320> );
	LUA->SetField( -2, "ripemd320" );
}

}

GMOD_MODULE_OPEN( )
{
	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->CreateTable( );

	crypt::Initialize( state );
	hasher::Initialize( state );

	LUA->SetField( -2, "crypt" );

	LUA->Pop( 1 );
	return 0;
}

GMOD_MODULE_CLOSE( )
{
	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->PushNil( );
	LUA->SetField( -2, "crypt" );

	LUA->Pop( 1 );
	return 0;
}