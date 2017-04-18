#pragma once

namespace GarrysMod
{
	namespace Lua
	{
		class ILuaBase;
	}
}

namespace crypt
{

void Initialize( GarrysMod::Lua::ILuaBase *LUA );
void Deinitialize( GarrysMod::Lua::ILuaBase *LUA );

}
