#include <cryptography.hpp>
#include <stdexcept>
#include <iostream>

int main( int argc, char *argv[] )
{
	cryptography::bytes primary( 32, 'a' );
	cryptography::bytes secondary( 16, 'a' );

	cryptography::AES aes;

	primary = aes.GeneratePrimaryKey( 256 );
	if( primary.empty( ) )
		throw std::runtime_error( aes.GetLastError( ) );

	secondary = aes.GenerateSecondaryKey( 256 );
	if( secondary.empty( ) )
		throw std::runtime_error( aes.GetLastError( ) );

	cryptography::ECP ecp;

	primary = ecp.GeneratePrimaryKey( 256 );
	if( primary.empty( ) )
		throw std::runtime_error( ecp.GetLastError( ) );

	secondary = ecp.GenerateSecondaryKey( primary );
	if( secondary.empty( ) )
		throw std::runtime_error( ecp.GetLastError( ) );

	cryptography::RSA rsa;

	primary = rsa.GeneratePrimaryKey( 2048 );
	if( primary.empty( ) )
		throw std::runtime_error( rsa.GetLastError( ) );

	secondary = rsa.GenerateSecondaryKey( primary );
	if( secondary.empty( ) )
		throw std::runtime_error( rsa.GetLastError( ) );

	return 0;
}
