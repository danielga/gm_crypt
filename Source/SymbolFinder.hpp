#pragma once

#include <stdint.h>
#include <stddef.h>

#if !defined _WIN32

#include <vector>

#endif

class SymbolFinder
{
public:
	SymbolFinder( );
	~SymbolFinder( );

	void *FindPattern( void *handle, const uint8_t *pattern, size_t len );
	void *FindSymbol( void *handle, const char *symbol );
	void *FindSymbolFromBinary( const char *name, const char *symbol );

	// data can be a symbol name (if appended by @) or a pattern
	void *Resolve( void *handle, const char *data, size_t len = 0 );
	void *ResolveOnBinary( const char *name, const char *data, size_t len = 0 );

private:
	bool GetLibraryInfo( void *handle, struct DynLibInfo &info );

#if defined __linux

	std::vector<struct LibSymbolTable *> symbolTables;

#elif defined __APPLE__

	std::vector<struct LibSymbolTable *> symbolTables;
	struct dyld_all_image_infos *m_ImageList;
	int m_OSXMajor;
	int m_OSXMinor;

#endif

};