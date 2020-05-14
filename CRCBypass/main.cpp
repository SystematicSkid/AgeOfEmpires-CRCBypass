#include <windows.h>
#include <iostream>
#include <fstream>
#include <Psapi.h>
#include <algorithm>
#include <stdio.h>
#include <cstdio>
#include <ctime>
#include "age3y.h"
#include "age3.h"
#include "crc32.h"

/*
	The following functions meant to be a minimalistic hook, didn't bother to put these
		 functions in their respective files, eg. Memory.h/Memory.cpp
*/

using ptr = uintptr_t;
using uint = unsigned int;
using uint = unsigned int;
using uchar = unsigned char;
using ulong = unsigned long;

static std::string HexToBytes(std::string hex)
{
	std::string bytes;

	hex.erase(std::remove_if(hex.begin(), hex.end(), isspace), hex.end());

	for (uint i = 0; i < hex.length(); i += 2)
	{
		if ((uchar)hex[i] == '?')
		{
			bytes += '?';
			i -= 1;

			continue;
		}

		uchar byte = (uchar)std::strtol(hex.substr(i, 2).c_str(), nullptr, 16);
		bytes += byte;
	}

	return bytes;
}
static ptr SigScan(const char* pattern)
{

	HMODULE mod = GetModuleHandle(0);
	MODULEINFO info;
	GetModuleInformation(GetCurrentProcess(), mod, &info, sizeof(info));

	uchar* base = (uchar*)mod;

	std::string signature = HexToBytes(pattern);

	uchar first = (uchar)signature.at(0);
	uchar* end = (base + info.SizeOfImage) - signature.length();

	for (; base < end; ++base)
	{
		if (*base != first)
			continue;

		uchar* bytes = base;
		uchar* sig = (uchar*)signature.c_str();

		for (; *sig; ++sig, ++bytes)
		{
			if (*sig == '?')
				continue;

			if (*bytes != *sig)
				goto end;
		}

		return (ptr)base;

	end:;
	}

	return NULL;
}
static ptr GetCallAddress(const char* pattern)
{
	auto address = SigScan(pattern);
	if (!address)
	{
		return 0x0;
	}
	uintptr_t call_addr = (address + *(signed long*)(address + 1) + 5);
	return call_addr;
}

/* CRC Prototype File Bypass */

unsigned long *g_PrototypeCRC;

static INT iter = 0;

BOOL hashing_proto = false;

unsigned long __cdecl CRC32(unsigned long crc, BYTE* buf, unsigned int length)
{
	auto result = Engine::CRC32::Hash(crc, buf, length);

	if (strstr((PCHAR)buf, ("<Proto version ='"))) // Only prototype files have this header
	{
		printf("[ - ] Spoofing prototype file...\n");
		hashing_proto = TRUE;
	}

	if (hashing_proto)
	{
		result = g_PrototypeCRC[iter++];
	}

	if (strstr((PCHAR)buf, "</Proto>"))	// Find end of file
	{
		hashing_proto = FALSE;
		iter = 0;				// Reset our counter in case they want to scan the file again... 
		printf("[ - ] Finished spoofing protoype file!\n");
	}

	return result;
}

VOID Init()
{

	AllocConsole();
	SetConsoleCtrlHandler(NULL, true);
	FILE* fIn;
	FILE* fOut;
	freopen_s(&fIn, "conin$", "r", stdin);
	freopen_s(&fOut, "conout$", "w", stdout);

	printf("[ = ] Age of Empires 3 CRC Bypass by Sebastien#6214\n\n");
	printf("[ + ] Initializing...\n");

	ptr crc32_function = GetCallAddress("E8 ? ? ? ? EB 05 E8 ? ? ? ? 83 C4 0C");
	if (!crc32_function)
		return;

	/* Hook the crc32 function */

	/*
	 8B 4C 24 08                             mov     ecx, [esp+buf]
	 85 C9                                   test    ecx, ecx
	*/
	DWORD old_protection;
	VirtualProtect((PVOID)crc32_function, 6, PAGE_EXECUTE_READWRITE, &old_protection); // Microshaft write protection
	*(BYTE*)(crc32_function + 0x0) = 0xE9; // far jmp
	*(DWORD*)(crc32_function + 0x1) = (DWORD)(&CRC32) - crc32_function - 0x5;
	*(BYTE*)(crc32_function + 0x5) = 0x90; // nop remaining byte
	VirtualProtect((PVOID)crc32_function, 6, old_protection, &old_protection);

	if (GetModuleHandleA("age3.exe")) // Vanilla crc hash
	{
		g_PrototypeCRC = new unsigned long[sizeof g_VanillaCRC];
		g_PrototypeCRC = g_VanillaCRC;
		printf("\t[ + ] Loaded Vanilla Hashes\n");
	}

	else if (GetModuleHandleA("age3y.exe"))
	{
		g_PrototypeCRC = new unsigned long[sizeof g_AsianCRC];
		g_PrototypeCRC = g_AsianCRC;
		printf("\t[ + ] Loaded Asian Dynasty Hashes\n");

	}

	printf("[ + ] Engine Initialized Successfully...\nGLHF\n");

	return;
}

DWORD WINAPI DllMain(_In_ void* _DllHandle, _In_ unsigned long _Reason, _In_opt_ void* _Reserved)
{
	if (_Reason == DLL_PROCESS_ATTACH)
	{
		Init();
		return TRUE;
	}
	return FALSE;
}

