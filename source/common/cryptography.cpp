#include <cryptography.hpp>

namespace cryptography
{
	AES::AES( ) :
		ivset( false ),
		keyset( false )
	{ }

	std::string AES::AlgorithmName( ) const
	{
		return encrypter.AlgorithmName( );
	}

	size_t AES::MaxPlaintextLength( size_t length ) const
	{
		length /= 8;

		size_t remainder = length % CryptoPP::AES::BLOCKSIZE;
		if( remainder == 0 )
			return length;

		return length + CryptoPP::AES::BLOCKSIZE - remainder;
	}

	size_t AES::CiphertextLength( size_t length ) const
	{
		length /= 8;

		size_t remainder = length % CryptoPP::AES::BLOCKSIZE;
		if( remainder == 0 )
			return length;

		return length + CryptoPP::AES::BLOCKSIZE - remainder;
	}

	size_t AES::FixedMaxPlaintextLength( ) const
	{
		return CryptoPP::AES::BLOCKSIZE * 8;
	}

	size_t AES::FixedCiphertextLength( ) const
	{
		return CryptoPP::AES::BLOCKSIZE * 8;
	}

	size_t AES::GetValidPrimaryKeyLength( size_t length ) const
	{
		return encrypter.GetValidKeyLength( length / 8 );
	}

	bytes AES::GeneratePrimaryKey( size_t priSize )
	{
		priSize /= 8;

		if( !encrypter.IsValidKeyLength( priSize ) )
		{
			SetLastError( "Invalid AES key length" );
			return bytes( );
		}

		try
		{
			bytes priKey;
			priKey.resize( priSize );
			CryptoPP::AutoSeededRandomPool( ).GenerateBlock( priKey.data( ), priSize );
			return priKey;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return bytes( );
		}
	}

	bool AES::SetPrimaryKey( const bytes &priKey )
	{
		try
		{
			SetKey( priKey );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	size_t AES::GetValidSecondaryKeyLength( size_t length ) const
	{
		return encrypter.GetValidKeyLength( length / 8 );
	}

	bytes AES::GenerateSecondaryKey( size_t secSize )
	{
		secSize /= 8;

		if( !encrypter.IsValidKeyLength( secSize ) )
		{
			SetLastError( "Invalid AES IV length" );
			return bytes( );
		}

		try
		{
			bytes secKey;
			secKey.resize( secSize );
			CryptoPP::AutoSeededRandomPool( ).GenerateBlock( secKey.data( ), secSize );
			return secKey;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return bytes( );
		}
	}

	bytes AES::GenerateSecondaryKey( const bytes & )
	{
		SetLastError( "Tried to generate an IV from an AES key" );
		return bytes( );
	}

	bool AES::SetSecondaryKey( const bytes &secKey )
	{
		try
		{
			SetIV( secKey );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	bool AES::Decrypt( const bytes &encrypted, bytes &decrypted )
	{
		try
		{
			CheckKey( );
			decrypted.resize( encrypted.size( ) );
			decrypter.ProcessData( decrypted.data( ), encrypted.data( ), encrypted.size( ) );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	bool AES::Encrypt( const bytes &decrypted, bytes &encrypted )
	{
		try
		{
			CheckKey( );
			encrypted.resize( decrypted.size( ) );
			encrypter.ProcessData( encrypted.data( ), decrypted.data( ), decrypted.size( ) );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	void AES::CheckIV( ) const
	{
		if( !ivset )
			throw CryptoPP::Exception( CryptoPP::Exception::OTHER_ERROR, "AES IV was not set" );
	}

	void AES::CheckKey( ) const
	{
		if( !keyset )
			throw CryptoPP::Exception( CryptoPP::Exception::OTHER_ERROR, "AES key was not set" );
	}

	void AES::SetKey( const bytes &priKey )
	{
		CheckIV( );
		decrypter.SetKeyWithIV( priKey.data( ), priKey.size( ), iv );
		encrypter.SetKeyWithIV( priKey.data( ), priKey.size( ), iv );
		keyset = true;
	}

	void AES::SetIV( const bytes &secKey )
	{
		if( keyset )
		{
			decrypter.Resynchronize( secKey.data( ), secKey.size( ) );
			encrypter.Resynchronize( secKey.data( ), secKey.size( ) );
		}

		std::copy( secKey.begin( ), secKey.end( ), iv );
		ivset = true;
	}

	RSA::RSA( ) :
		prikeyset( false ),
		pubkeyset( false )
	{ }

	std::string RSA::AlgorithmName( ) const
	{
		return encrypter.AlgorithmName( );
	}

	size_t RSA::MaxPlaintextLength( size_t length ) const
	{
		return encrypter.MaxPlaintextLength( length );
	}

	size_t RSA::CiphertextLength( size_t length ) const
	{
		return encrypter.CiphertextLength( length );
	}

	size_t RSA::FixedMaxPlaintextLength( ) const
	{
		return encrypter.FixedMaxPlaintextLength( );
	}

	size_t RSA::FixedCiphertextLength( ) const
	{
		return encrypter.FixedCiphertextLength( );
	}

	size_t RSA::GetValidPrimaryKeyLength( size_t length ) const
	{
		return length;
	}

	bytes RSA::GeneratePrimaryKey( size_t priSize )
	{
		try
		{
			CryptoPP::RSA::PrivateKey privKey;

			CryptoPP::AutoSeededRandomPool prng;
			privKey.GenerateRandomWithKeySize( prng, priSize );

			bytes_string priStr;
			bytes_sink privSink( priStr );
			privKey.Save( privSink.Ref( ) );

			return bytes( priStr.begin( ), priStr.end( ) );
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return bytes( );
		}
	}

	bool RSA::SetPrimaryKey( const bytes &priKey )
	{
		try
		{
			CryptoPP::RSA::PrivateKey privKey;
			CryptoPP::StringSource stringSource( priKey.data( ), priKey.size( ), true );
			privKey.Load( stringSource.Ref( ) );
			SetPrivateKey( privKey );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	size_t RSA::GetValidSecondaryKeyLength( size_t length ) const
	{
		return length;
	}

	bytes RSA::GenerateSecondaryKey( size_t )
	{
		SetLastError( "RSA private key is required to generate a public key" );
		return bytes( );
	}

	bytes RSA::GenerateSecondaryKey( const bytes &priKey )
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

			return bytes( secStr.begin( ), secStr.end( ) );
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return bytes( );
		}
	}

	bool RSA::SetSecondaryKey( const bytes &secKey )
	{
		try
		{
			CryptoPP::RSA::PublicKey pubKey;
			CryptoPP::StringSource stringSource( secKey.data( ), secKey.size( ), true );
			pubKey.Load( stringSource.Ref( ) );
			SetPublicKey( pubKey );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	bool RSA::Decrypt( const bytes &encrypted, bytes &decrypted )
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
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	bool RSA::Encrypt( const bytes &decrypted, bytes &encrypted )
	{
		try
		{
			CheckPublicKey( );
			CryptoPP::AutoSeededRandomPool prng;
			encrypted.resize( encrypter.CiphertextLength( decrypted.size( ) ) );
			encrypter.Encrypt( prng, decrypted.data( ), decrypted.size( ), encrypted.data( ) );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	void RSA::CheckPrivateKey( ) const
	{
		if( !prikeyset )
			throw CryptoPP::Exception(
				CryptoPP::Exception::OTHER_ERROR,
				"RSA private key was not set"
			);
	}

	void RSA::SetPrivateKey( const CryptoPP::RSA::PrivateKey &privKey )
	{
		decrypter.AccessKey( ).AssignFrom( privKey );
		prikeyset = true;
	}

	void RSA::CheckPublicKey( ) const
	{
		if( !pubkeyset )
			throw CryptoPP::Exception(
				CryptoPP::Exception::OTHER_ERROR,
				"RSA public key was not set"
			);
	}

	void RSA::SetPublicKey( const CryptoPP::RSA::PublicKey &pubKey )
	{
		encrypter.AccessKey( ).AssignFrom( pubKey );
		pubkeyset = true;
	}

	ECP::ECP( ) :
		prikeyset( false ),
		pubkeyset( false )
	{ }

	std::string ECP::AlgorithmName( ) const
	{
		return encrypter.AlgorithmName( );
	}

	size_t ECP::MaxPlaintextLength( size_t length ) const
	{
		return encrypter.MaxPlaintextLength( length );
	}

	size_t ECP::CiphertextLength( size_t length ) const
	{
		return encrypter.CiphertextLength( length );
	}

	size_t ECP::FixedMaxPlaintextLength( ) const
	{
		return encrypter.FixedMaxPlaintextLength( );
	}

	size_t ECP::FixedCiphertextLength( ) const
	{
		return encrypter.FixedCiphertextLength( );
	}

	size_t ECP::GetValidPrimaryKeyLength( size_t length ) const
	{
		return length;
	}

	bytes ECP::GeneratePrimaryKey( size_t priSize )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;

			CryptoPP::AutoSeededRandomPool prng;
			privKey.GenerateRandomWithKeySize( prng, priSize );

			bytes_string priStr;
			bytes_sink privSink( priStr );
			privKey.Save( privSink.Ref( ) );

			return bytes( priStr.begin( ), priStr.end( ) );
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return bytes( );
		}
	}

	bool ECP::SetPrimaryKey( const bytes &priKey )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey privKey;
			CryptoPP::StringSource stringSource( priKey.data( ), priKey.size( ), true );
			privKey.Load( stringSource.Ref( ) );
			SetPrivateKey( privKey );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	size_t ECP::GetValidSecondaryKeyLength( size_t length ) const
	{
		return length;
	}

	bytes ECP::GenerateSecondaryKey( size_t )
	{
		SetLastError( "ECP private key is required to generate a public key" );
		return bytes( );
	}

	bytes ECP::GenerateSecondaryKey( const bytes &priKey )
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

			return bytes( secStr.begin( ), secStr.end( ) );
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return bytes( );
		}
	}

	bool ECP::SetSecondaryKey( const bytes &secKey )
	{
		try
		{
			CryptoPP::ECIES<CryptoPP::ECP>::PublicKey pubKey;
			CryptoPP::StringSource stringSource( secKey.data( ), secKey.size( ), true );
			pubKey.Load( stringSource.Ref( ) );
			SetPublicKey( pubKey );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	bool ECP::Decrypt( const bytes &encrypted, bytes &decrypted )
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
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	bool ECP::Encrypt( const bytes &decrypted, bytes &encrypted )
	{
		try
		{
			CheckPublicKey( );
			CryptoPP::AutoSeededRandomPool prng;
			encrypted.resize( encrypter.CiphertextLength( decrypted.size( ) ) );
			encrypter.Encrypt( prng, decrypted.data( ), decrypted.size( ), encrypted.data( ) );
			return true;
		}
		catch( const CryptoPP::Exception &e )
		{
			SetLastError( e.GetWhat( ) );
			return false;
		}
	}

	void ECP::CheckPrivateKey( ) const
	{
		if( !prikeyset )
			throw CryptoPP::Exception(
				CryptoPP::Exception::OTHER_ERROR,
				"ECP private key was not set"
			);
	}

	void ECP::SetPrivateKey( const CryptoPP::ECIES<CryptoPP::ECP>::PrivateKey &privKey )
	{
		decrypter.AccessKey( ).AssignFrom( privKey );
		prikeyset = true;
	}

	void ECP::CheckPublicKey( ) const
	{
		if( !pubkeyset )
			throw CryptoPP::Exception(
				CryptoPP::Exception::OTHER_ERROR,
				"ECP public key was not set"
			);
	}

	void ECP::SetPublicKey( const CryptoPP::ECIES<CryptoPP::ECP>::PublicKey &pubKey )
	{
		encrypter.AccessKey( ).AssignFrom( pubKey );
		pubkeyset = true;
	}
}
