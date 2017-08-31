#include <cryptography.hpp>
#include <stdexcept>
#include <iostream>

int main( int argc, char *argv[] )
{
	cryptography::bytes primary( 32, 'a' );
	cryptography::bytes secondary( 16, 'a' );

	cryptography::AES aes;

	secondary = aes.GenerateSecondaryKey( 16 );
	if( secondary.empty( ) )
		throw std::runtime_error( aes.GetLastError( ) );

	primary = aes.GeneratePrimaryKey( 32 );
	if( primary.empty( ) )
		throw std::runtime_error( aes.GetLastError( ) );

	// ECP requires pre-built elliptical curve, random generator not implemented
	cryptography::ECP ecp;

	primary = ecp.GeneratePrimaryKey( 32 );
	if( primary.empty( ) )
		std::cout << ecp.GetLastError( ) << std::endl;

	secondary = ecp.GenerateSecondaryKey( primary );
	if( secondary.empty( ) )
		std::cout << ecp.GetLastError( ) << std::endl;

	cryptography::RSA rsa;

	primary = rsa.GeneratePrimaryKey( 512 );
	if( primary.empty( ) )
		throw std::runtime_error( rsa.GetLastError( ) );

	secondary = rsa.GenerateSecondaryKey( primary );
	if( secondary.empty( ) )
		throw std::runtime_error( rsa.GetLastError( ) );

	return 0;
}
