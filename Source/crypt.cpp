#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <GarrysMod/Lua/Interface.h>
#include <cryptopp/base64.h>
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
#include <cryptopp/hex.h>

#define LUA_ERROR( ) ( LUA->ThrowError( LUA->GetString( ) ), 0 )

LUA_FUNCTION( lBase64Encode )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );

	size_t dataLength = 0;
	const byte *data = reinterpret_cast<const byte *>( LUA->GetString( 1, &dataLength ) );

	try
	{
		std::string encoded;
		CryptoPP::StringSource( data, dataLength, true,
			new CryptoPP::Base64Encoder(
				new CryptoPP::StringSink( encoded ), false
			)
		);

		LUA->PushString( encoded.c_str( ), encoded.size( ) );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION( lBase64Decode )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );

	size_t dataLength = 0;
	const byte *data = reinterpret_cast<const byte *>( LUA->GetString( 1, &dataLength ) );

	try
	{
		std::string decoded;
		CryptoPP::StringSource( data, dataLength, true,
			new CryptoPP::Base64Decoder(
				new CryptoPP::StringSink( decoded )
			)
		);

		LUA->PushString( decoded.c_str( ), decoded.size( ) );
		return 1;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION( lAESEncrypt )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 3, GarrysMod::Lua::Type::STRING );

	size_t keyLen = 0;
	const byte *key = reinterpret_cast<const byte *>( LUA->GetString( 2, &keyLen ) );
	if( keyLen != 16 && keyLen != 24 && keyLen != 32 )
	{
		LUA->ThrowError( "invalid key length supplied" );
		return 0;
	}

	size_t ivLen = 0;
	const byte *iv = reinterpret_cast<const byte *>( LUA->GetString( 3, &ivLen ) );
	if( ivLen != 16 && ivLen != 24 && ivLen != 32 )
	{
		LUA->ThrowError( "invalid IV length supplied" );
		return 0;
	}

	size_t dataLength = 0;
	const byte *data = reinterpret_cast<const byte *>( LUA->GetString( 1, &dataLength ) );

	try
	{
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
		encryptor.SetKeyWithIV( key, keyLen, iv, ivLen );

		std::string encrypted;
		CryptoPP::StringSource( data, dataLength, true,
			new CryptoPP::StreamTransformationFilter( encryptor,
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

LUA_FUNCTION( lAESDecrypt )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 3, GarrysMod::Lua::Type::STRING );

	size_t keyLen = 0;
	const byte *key = reinterpret_cast<const byte *>( LUA->GetString( 2, &keyLen ) );
	if( keyLen != 16 && keyLen != 24 && keyLen != 32 )
	{
		LUA->ThrowError( "invalid key length supplied" );
		return 0;
	}

	size_t ivLen = 0;
	const byte *iv = reinterpret_cast<const byte *>( LUA->GetString( 3, &ivLen ) );
	if( ivLen != 16 && ivLen != 24 && ivLen != 32 )
	{
		LUA->ThrowError( "invalid IV length supplied" );
		return 0;
	}

	size_t dataLength = 0;
	const byte *data = reinterpret_cast<const byte *>( LUA->GetString( 1, &dataLength ) );

	try
	{
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
		decryptor.SetKeyWithIV( key, keyLen, iv, ivLen );

		std::string decrypted;
		CryptoPP::StringSource( data, dataLength, true,
			new CryptoPP::StreamTransformationFilter( decryptor,
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

LUA_FUNCTION( lRSAGenKeyPair )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::NUMBER );
	unsigned int size = static_cast<unsigned int>( LUA->GetNumber( 1 ) );

	try
	{
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::InvertibleRSAFunction func;
		func.GenerateRandomWithKeySize( rng, size );

		CryptoPP::RSA::PrivateKey privKey( func );
		std::string privateKey;
		CryptoPP::StringSink privSink( privateKey );
		privKey.Save( static_cast<CryptoPP::BufferedTransformation &>( privSink ) );

		CryptoPP::RSA::PublicKey pubKey( func );
		std::string publicKey;
		CryptoPP::StringSink pubSink( publicKey );
		pubKey.Save( static_cast<CryptoPP::BufferedTransformation &>( pubSink ) );

		LUA->PushString( privateKey.c_str( ), privateKey.size( ) );
		LUA->PushString( publicKey.c_str( ), publicKey.size( ) );
		return 2;
	}
	catch( std::exception &e )
	{
		LUA->PushString( e.what( ) );
	}

	return LUA_ERROR( );
}

LUA_FUNCTION( lRSAEncrypt )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t dataLength = 0;
	const byte *data = reinterpret_cast<const byte *>( LUA->GetString( 1, &dataLength ) );

	size_t publicKeyLen = 0;
	const byte *publicKey = reinterpret_cast<const byte *>( LUA->GetString( 2, &publicKeyLen ) );

	try
	{
		CryptoPP::RSA::PublicKey pubKey;
		CryptoPP::ByteQueue queue;
		queue.Put( publicKey, publicKeyLen );
		queue.MessageEnd( );
		pubKey.Load( queue );

		std::string encrypted;
		CryptoPP::RSAES_OAEP_SHA_Encryptor enc( pubKey );
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::StringSource( data, dataLength, true,
			new CryptoPP::PK_EncryptorFilter( static_cast<CryptoPP::RandomNumberGenerator &>( rng ), enc,
				static_cast<CryptoPP::BufferedTransformation *>( new CryptoPP::StringSink( encrypted ) )
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

LUA_FUNCTION( lRSADecrypt )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );
	LUA->CheckType( 2, GarrysMod::Lua::Type::STRING );

	size_t dataLength = 0;
	const byte *data = reinterpret_cast<const byte *>( LUA->GetString( 1, &dataLength ) );

	size_t privateKeyLen = 0;
	const byte *privateKey = reinterpret_cast<const byte *>( LUA->GetString( 2, &privateKeyLen ) );

	try
	{
		CryptoPP::RSA::PrivateKey privKey;
		CryptoPP::ByteQueue queue;
		queue.Put( privateKey, privateKeyLen );
		queue.MessageEnd( );
		privKey.Load( queue );

		std::string decrypted;
		CryptoPP::RSAES_OAEP_SHA_Decryptor dec( privKey );
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::StringSource( data, dataLength, true,
			new CryptoPP::PK_DecryptorFilter( static_cast<CryptoPP::RandomNumberGenerator &>( rng ), dec,
				static_cast<CryptoPP::BufferedTransformation *>( new CryptoPP::StringSink( decrypted ) )
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

#define HashFunc( funcName, hashType )												\
LUA_FUNCTION( funcName )															\
{																					\
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );								\
	if( LUA->Top( ) > 1 )															\
		LUA->CheckType( 2, GarrysMod::Lua::Type::BOOL );							\
																					\
	size_t len = 0;																	\
	const byte *in = reinterpret_cast<const byte *>( LUA->GetString( 1, &len ) );	\
																					\
	bool errored = false;															\
	byte out[CryptoPP::hashType::DIGESTSIZE];										\
	try																				\
	{																				\
		CryptoPP::hashType( ).CalculateDigest( out, in, len );						\
	}																				\
	catch( std::exception &e )														\
	{																				\
		LUA->PushString( e.what( ) );												\
		errored = true;																\
	}																				\
																					\
	if( errored )																	\
		return LUA_ERROR( );														\
																					\
	if( LUA->GetBool( ) )															\
	{																				\
		LUA->PushString( reinterpret_cast<const char *>( out ), CryptoPP::hashType::DIGESTSIZE );	\
		return 1;																	\
	}																				\
																					\
	std::string hexOut;																\
	CryptoPP::StringSource( out, CryptoPP::hashType::DIGESTSIZE, true,				\
		new CryptoPP::HexEncoder( new CryptoPP::StringSink( hexOut ) )				\
	);																				\
																					\
	LUA->PushString( hexOut.c_str( ), hexOut.size( ) );								\
	return 1;																		\
}

static const unsigned short wCRCTable[] = {
	0X0000, 0XC0C1, 0XC181, 0X0140, 0XC301, 0X03C0, 0X0280, 0XC241,
	0XC601, 0X06C0, 0X0780, 0XC741, 0X0500, 0XC5C1, 0XC481, 0X0440,
	0XCC01, 0X0CC0, 0X0D80, 0XCD41, 0X0F00, 0XCFC1, 0XCE81, 0X0E40,
	0X0A00, 0XCAC1, 0XCB81, 0X0B40, 0XC901, 0X09C0, 0X0880, 0XC841,
	0XD801, 0X18C0, 0X1980, 0XD941, 0X1B00, 0XDBC1, 0XDA81, 0X1A40,
	0X1E00, 0XDEC1, 0XDF81, 0X1F40, 0XDD01, 0X1DC0, 0X1C80, 0XDC41,
	0X1400, 0XD4C1, 0XD581, 0X1540, 0XD701, 0X17C0, 0X1680, 0XD641,
	0XD201, 0X12C0, 0X1380, 0XD341, 0X1100, 0XD1C1, 0XD081, 0X1040,
	0XF001, 0X30C0, 0X3180, 0XF141, 0X3300, 0XF3C1, 0XF281, 0X3240,
	0X3600, 0XF6C1, 0XF781, 0X3740, 0XF501, 0X35C0, 0X3480, 0XF441,
	0X3C00, 0XFCC1, 0XFD81, 0X3D40, 0XFF01, 0X3FC0, 0X3E80, 0XFE41,
	0XFA01, 0X3AC0, 0X3B80, 0XFB41, 0X3900, 0XF9C1, 0XF881, 0X3840,
	0X2800, 0XE8C1, 0XE981, 0X2940, 0XEB01, 0X2BC0, 0X2A80, 0XEA41,
	0XEE01, 0X2EC0, 0X2F80, 0XEF41, 0X2D00, 0XEDC1, 0XEC81, 0X2C40,
	0XE401, 0X24C0, 0X2580, 0XE541, 0X2700, 0XE7C1, 0XE681, 0X2640,
	0X2200, 0XE2C1, 0XE381, 0X2340, 0XE101, 0X21C0, 0X2080, 0XE041,
	0XA001, 0X60C0, 0X6180, 0XA141, 0X6300, 0XA3C1, 0XA281, 0X6240,
	0X6600, 0XA6C1, 0XA781, 0X6740, 0XA501, 0X65C0, 0X6480, 0XA441,
	0X6C00, 0XACC1, 0XAD81, 0X6D40, 0XAF01, 0X6FC0, 0X6E80, 0XAE41,
	0XAA01, 0X6AC0, 0X6B80, 0XAB41, 0X6900, 0XA9C1, 0XA881, 0X6840,
	0X7800, 0XB8C1, 0XB981, 0X7940, 0XBB01, 0X7BC0, 0X7A80, 0XBA41,
	0XBE01, 0X7EC0, 0X7F80, 0XBF41, 0X7D00, 0XBDC1, 0XBC81, 0X7C40,
	0XB401, 0X74C0, 0X7580, 0XB541, 0X7700, 0XB7C1, 0XB681, 0X7640,
	0X7200, 0XB2C1, 0XB381, 0X7340, 0XB101, 0X71C0, 0X7080, 0XB041,
	0X5000, 0X90C1, 0X9181, 0X5140, 0X9301, 0X53C0, 0X5280, 0X9241,
	0X9601, 0X56C0, 0X5780, 0X9741, 0X5500, 0X95C1, 0X9481, 0X5440,
	0X9C01, 0X5CC0, 0X5D80, 0X9D41, 0X5F00, 0X9FC1, 0X9E81, 0X5E40,
	0X5A00, 0X9AC1, 0X9B81, 0X5B40, 0X9901, 0X59C0, 0X5880, 0X9841,
	0X8801, 0X48C0, 0X4980, 0X8941, 0X4B00, 0X8BC1, 0X8A81, 0X4A40,
	0X4E00, 0X8EC1, 0X8F81, 0X4F40, 0X8D01, 0X4DC0, 0X4C80, 0X8C41,
	0X4400, 0X84C1, 0X8581, 0X4540, 0X8701, 0X47C0, 0X4680, 0X8641,
	0X8201, 0X42C0, 0X4380, 0X8341, 0X4100, 0X81C1, 0X8081, 0X4040
};

LUA_FUNCTION( lCRC16 )
{
	LUA->CheckType( 1, GarrysMod::Lua::Type::STRING );

	size_t wLength = 0;
	const byte *nData = reinterpret_cast<const byte *>( LUA->GetString( 1, &wLength ) );

	byte nTemp;
	unsigned short wCRCWord = 0;
	while( wLength-- )
	{
		nTemp = *nData++ ^ wCRCWord;
		wCRCWord >>= 8;
		wCRCWord ^= wCRCTable[nTemp];
	}

	std::string hexOut;
	CryptoPP::StringSource( reinterpret_cast<const byte *>( wCRCWord ), 2, true,
		new CryptoPP::HexEncoder( new CryptoPP::StringSink( hexOut ) )
	);

	LUA->PushString( hexOut.c_str( ), hexOut.size( ) );
	return 1;
}

#define SetCryptFunc( name, funcName )	\
	LUA->PushCFunction( funcName );		\
	LUA->SetField( -2, name );

HashFunc( lCRC32, CRC32 );

HashFunc( lSha1, SHA1 );
HashFunc( lSha256, SHA256 );
HashFunc( lSha224, SHA224 );
HashFunc( lSha384, SHA384 );
HashFunc( lSha512, SHA512 );

HashFunc( lTiger, Tiger );

HashFunc( lWhirlPool, Whirlpool );

HashFunc( lMd2, Weak::MD2 );
HashFunc( lMd4, Weak::MD4 );
HashFunc( lMd5, Weak::MD5 );

HashFunc( lRipeMod128, RIPEMD128 );
HashFunc( lRipeMod160, RIPEMD160 );
HashFunc( lRipeMod256, RIPEMD256 );
HashFunc( lRipeMod320, RIPEMD320 );

GMOD_MODULE_OPEN( )
{
	LUA->PushSpecial( GarrysMod::Lua::SPECIAL_GLOB );

	LUA->CreateTable( );

	SetCryptFunc( "crc16", lCRC16 );
	SetCryptFunc( "crc32", lCRC32 );

	SetCryptFunc( "sha1", lSha1 );
	SetCryptFunc( "sha224", lSha224 );
	SetCryptFunc( "sha238", lSha384 );
	SetCryptFunc( "sha256", lSha256 );
	SetCryptFunc( "sha512", lSha512 );

	SetCryptFunc( "md2", lMd2 );
	SetCryptFunc( "md4", lMd4 );
	SetCryptFunc( "md5", lMd5 );

	SetCryptFunc( "ripeMod128", lRipeMod128 );
	SetCryptFunc( "ripeMod160", lRipeMod160 );
	SetCryptFunc( "ripeMod256", lRipeMod256 );
	SetCryptFunc( "ripeMod320", lRipeMod320 );

	SetCryptFunc( "aesEncrypt", lAESEncrypt );
	SetCryptFunc( "aesDecrypt", lAESDecrypt );

	SetCryptFunc( "rsaGenerateKeyPair", lRSAGenKeyPair );
	SetCryptFunc( "rsaEncrypt", lRSAEncrypt );
	SetCryptFunc( "rsaDecrypt", lRSADecrypt );

	SetCryptFunc( "base64Encode", lBase64Encode );
	SetCryptFunc( "base64Decode", lBase64Decode );

	LUA->SetField( -2, "crypt" );

	return 0;
}

GMOD_MODULE_CLOSE( )
{
	return 0;
}
