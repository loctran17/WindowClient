#include "stdafx.h"
#include "hwid.h"

char* GetProcessor()
{
	char  CPUkey[100] = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";
	char  CPUVal[100] = "ProcessorNameString";
	HKEY key1;

	char* buf = (char*)malloc(100);

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CPUkey, 0, KEY_READ, &key1) == ERROR_SUCCESS)
	{
		DWORD dataSize;

		RegQueryValueExA(key1, CPUVal, NULL, NULL, NULL, &dataSize);
		realloc(buf, dataSize);

		int result = RegQueryValueExA(key1, CPUVal, NULL, NULL, (PBYTE)buf, &dataSize);
	}

	RegCloseKey(key1);

	return buf;
}

char* GetMainBoard()
{
	char  CPUkey[100] = "HARDWARE\\DESCRIPTION\\System\\BIOS";
	char  CPUVal[100] = "BaseBoardProduct";
	HKEY key1;

	char* buf = (char*)malloc(100);

	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CPUkey, 0, KEY_READ, &key1) == ERROR_SUCCESS)
	{
		DWORD dataSize;

		RegQueryValueExA(key1, CPUVal, NULL, NULL, NULL, &dataSize);
		realloc(buf, dataSize);

		RegQueryValueExA(key1, CPUVal, NULL, NULL, (PBYTE)buf, &dataSize);
	}

	RegCloseKey(key1);

	return buf;
}

char* GetHWID()
{
	char *pOut = (char*)malloc(256);

	sprintf(pOut, "%s%s",
		GetMainBoard(),
		GetProcessor()
		);

	return pOut;
}