#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>

namespace cryptography
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

		virtual bytes GeneratePrimaryKey( size_t priSize ) = 0;

		virtual bool SetPrimaryKey( const bytes &priKey ) = 0;

		virtual size_t GetValidSecondaryKeyLength( size_t length ) const = 0;

		virtual bytes GenerateSecondaryKey( size_t secSize ) = 0;
		virtual bytes GenerateSecondaryKey( const bytes &priKey ) = 0;

		virtual bool SetSecondaryKey( const bytes &secKey ) = 0;

		virtual bool Decrypt( const bytes &data, bytes &decrypted ) = 0;

		virtual bool Encrypt( const bytes &data, bytes &encrypted ) = 0;

		inline const std::string &GetLastError( ) const
		{
			return lasterror;
		}

	protected:
		inline void SetLastError( const std::string &err )
		{
			lasterror = err;
		}

	private:
		std::string lasterror;
	};

	class AES : public Crypter
	{
	public:
		AES( );

		std::string AlgorithmName( ) const;

		size_t MaxPlaintextLength( size_t length ) const;

		size_t CiphertextLength( size_t length ) const;

		size_t FixedMaxPlaintextLength( ) const;

		size_t FixedCiphertextLength( ) const;

		size_t GetValidPrimaryKeyLength( size_t length ) const;

		bytes GeneratePrimaryKey( size_t priSize );

		bool SetPrimaryKey( const bytes &priKey );

		size_t GetValidSecondaryKeyLength( size_t length ) const;

		bytes GenerateSecondaryKey( size_t secSize );
		bytes GenerateSecondaryKey( const bytes & );

		bool SetSecondaryKey( const bytes &secKey );

		bool Decrypt( const bytes &encrypted, bytes &decrypted );

		bool Encrypt( const bytes &decrypted, bytes &encrypted );

	private:
		void CheckIV( ) const;

		void CheckKey( ) const;

		void SetKey( const bytes &priKey );

		void SetIV( const bytes &secKey );

		bool ivset;
		bool keyset;
		CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption decrypter;
		CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption encrypter;
		uint8_t iv[CryptoPP::AES::BLOCKSIZE];
	};

	class RSA : public Crypter
	{
	public:
		RSA( );

		std::string AlgorithmName( ) const;

		size_t MaxPlaintextLength( size_t length ) const;

		size_t CiphertextLength( size_t length ) const;

		size_t FixedMaxPlaintextLength( ) const;

		size_t FixedCiphertextLength( ) const;

		size_t GetValidPrimaryKeyLength( size_t length ) const;

		bytes GeneratePrimaryKey( size_t priSize );

		bool SetPrimaryKey( const bytes &priKey );

		size_t GetValidSecondaryKeyLength( size_t length ) const;

		bytes GenerateSecondaryKey( size_t secSize );
		bytes GenerateSecondaryKey( const bytes &priKey );

		bool SetSecondaryKey( const bytes &secKey );

		bool Decrypt( const bytes &encrypted, bytes &decrypted );

		bool Encrypt( const bytes &decrypted, bytes &encrypted );

	private:
		void CheckPrivateKey( ) const;

		void SetPrivateKey( const CryptoPP::RSA::PrivateKey &privKey );

		void CheckPublicKey( ) const;

		void SetPublicKey( const CryptoPP::RSA::PublicKey &pubKey );

		bool prikeyset;
		bool pubkeyset;
		CryptoPP::RSAES_OAEP_SHA_Decryptor decrypter;
		CryptoPP::RSAES_OAEP_SHA_Encryptor encrypter;
	};

	class ECP : public Crypter
	{
	public:
		ECP( );

		std::string AlgorithmName( ) const;

		size_t MaxPlaintextLength( size_t length ) const;

		size_t CiphertextLength( size_t length ) const;

		size_t FixedMaxPlaintextLength( ) const;

		size_t FixedCiphertextLength( ) const;

		size_t GetValidPrimaryKeyLength( size_t length ) const;

		bytes GeneratePrimaryKey( size_t priSize );

		bool SetPrimaryKey( const bytes &priKey );

		size_t GetValidSecondaryKeyLength( size_t length ) const;

		bytes GenerateSecondaryKey( size_t secSize );
		bytes GenerateSecondaryKey( const bytes &priKey );

		bool SetSecondaryKey( const bytes &secKey );

		bool Decrypt( const bytes &encrypted, bytes &decrypted );

		bool Encrypt( const bytes &decrypted, bytes &encrypted );

	private:
		void CheckPrivateKey( ) const;

		void SetPrivateKey( const CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey &privKey );

		void CheckPublicKey( ) const;

		void SetPublicKey( const CryptoPP::ECIES<CryptoPP::ECP>::PublicKey &pubKey );

		bool prikeyset;
		bool pubkeyset;
		CryptoPP::ECIES<CryptoPP::ECP>::Decryptor decrypter;
		CryptoPP::ECIES<CryptoPP::ECP>::Encryptor encrypter;
	};
}
