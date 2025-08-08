#include <windows.h>
#include <iostream>
#include <TCHAR.h> 

#include "ntos.h"
#include <iostream>
#include <map>
#include <wincrypt.h>
#include <string>
#include <fstream>
#include <vector>
#include <array>
#include <shlwapi.h>
#include <iostream>
VOID  SetEntryPointOffsetOfTargetProcess(int off);
#pragma comment(lib, "shlwapi.lib")
VOID SetFullPathInKernel(char* p);
VOID  SetTargetProcessFolderPath(char* processName);
int ExtractDir(char* out) {
	char path[MAX_PATH] = "C:\\Users\\Public\\Documents\\example.txt";
	memset(path, 0, MAX_PATH);
	memcpy(path, out, strlen(out));
	// Remove file name, leaving only the directory
	if (PathRemoveFileSpecA(path)) {
		//std::cout << "Directory: " << path << std::endl;
		int abc = 0;
	}
	else {
		std::cerr << "Failed to extract path" << std::endl;
	}
	memset(out, 0, MAX_PATH);
	memcpy(out, path, strlen(path));
	return 0;
}
int AskKernelIfTargetProcessIsCrashed();
VOID ResumeSleepThread();
VOID TerminateTargetProcess(int pid);
#include <iostream>
#include "..\driver\shared.h"
int CheckProcessPPL(DWORD pid);
VOID RestoreObjCallback(DWORD64 funcAddr, char* _3bytes);
int gEhtread_startAddrOff;
#pragma comment(lib, "advapi32.lib")

VOID  SetEntryRoutineHeadBytes(char* processName);
DWORD gPploff;
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
VOID SetTargetProcessName(char* processName );
#include <psapi.h>
#include <iostream>
#include <vector>

int GetPEEntryPointBytes(const char* filePath, std::vector<BYTE>& entryBytes) {
	HMODULE hNtdll;
	FARPROC pRtlUserThreadStart;
	DWORD epFOA = 0;
	DWORD epRVA = 0;
	IMAGE_NT_HEADERS* ntHeaders = nullptr;
	IMAGE_SECTION_HEADER* section = nullptr;
	HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open file.\n";
		return false;
	}

	HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!hMapping) {
		CloseHandle(hFile);
		std::cerr << "Failed to create file mapping.\n";
		return false;
	}

	BYTE* base = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!base) {
		CloseHandle(hMapping);
		CloseHandle(hFile);
		std::cerr << "Failed to map file view.\n";
		return false;
	}
	int retv = 0;
	// Parse DOS header
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)base;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS signature.\n";
		goto cleanup;
	}
	// Parse NT headers
	ntHeaders = (IMAGE_NT_HEADERS*)(base + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT signature.\n";
		goto cleanup;
	}
	epRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;


	// Locate the section containing the entry point
	section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
		DWORD startRVA = section->VirtualAddress;
		DWORD endRVA = startRVA + section->Misc.VirtualSize;

		if (epRVA >= startRVA && epRVA < endRVA) {
			retv = epRVA - section->VirtualAddress;
			epFOA = epRVA - section->VirtualAddress + section->PointerToRawData;
			break;
		}
	}

	if (epFOA == 0) {
		std::cerr << "Entry point not found in any section.\n";
		goto cleanup;
	}

	  hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		std::cerr << "Failed to get handle to ntdll.dll\n";
		return 1;
	}

	  pRtlUserThreadStart = GetProcAddress(hNtdll, "RtlUserThreadStart");

	  entryBytes.assign(epFOA+ base, epFOA + base +3);
	// Read 0x10 bytes at the entry point
	  //entryBytes.assign((BYTE*)pRtlUserThreadStart, (BYTE*)pRtlUserThreadStart + preSetEntryRoutineHeadBytesCount);
	UnmapViewOfFile(base);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	return epRVA;
cleanup:
	UnmapViewOfFile(base);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	return false;
}

void GetProcessPathByPid(DWORD pid,char* outBuf) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (hProcess == NULL) {
		std::cerr << "Failed to open process " << pid << ", error: " << GetLastError() << std::endl;
		return;
	}

	char path[MAX_PATH];
	DWORD size = MAX_PATH;
	if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
	//	std::cout << "PID: " << pid << ", Executable Path: " << path << std::endl;
		memcpy(outBuf, path, strlen(path));
	}
	else {
		std::cerr << "Failed to get image name, error: " << GetLastError() << std::endl;
	}

	CloseHandle(hProcess);
}

VOID GetNameByPID(DWORD pid, char* outBuf) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to take snapshot." << std::endl;
		return;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			//std::wcout << L"PID: " << pe32.th32ProcessID << L"  Name: " << pe32.szExeFile << std::endl;
			if (pe32.th32ProcessID == pid) {
				memcpy(outBuf, pe32.szExeFile, strlen(pe32.szExeFile));
				CloseHandle(hSnapshot);
				return;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	else {
		std::cerr << "Failed to get process info." << std::endl;
	}

	CloseHandle(hSnapshot);

}
int CheckIfPidExist(DWORD pid, char* outBuf) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to take snapshot." << std::endl;
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			//std::wcout << L"PID: " << pe32.th32ProcessID << L"  Name: " << pe32.szExeFile << std::endl;
			if (pe32.th32ProcessID == pid) {

				return 1;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	else {
		std::cerr << "Failed to get process info." << std::endl;
	}

	CloseHandle(hSnapshot);
	return 0;
}
VOID displaypplprocess() {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to take snapshot." << std::endl;
		return;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32)) {
		do {
			//std::wcout << L"PID: " << pe32.th32ProcessID << L"  Name: " << pe32.szExeFile << std::endl;
			if (CheckProcessPPL(pe32.th32ProcessID)) {
				printf("\t%s\t%d\n", pe32.szExeFile, pe32.th32ProcessID);
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	else {
		std::cerr << "Failed to get process info." << std::endl;
	}

	CloseHandle(hSnapshot);

}
int CheckProcessPPL(DWORD pid);
std::string GetFileMD5(const std::string& filePath) {
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE buffer[4096];
	DWORD bytesRead;
	BYTE hash[16];  // MD5 = 128-bit = 16 bytes
	DWORD hashLen = sizeof(hash);
	std::string result;

	HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return "";

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		goto cleanup;

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		goto cleanup;

	while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
		if (!CryptHashData(hHash, buffer, bytesRead, 0))
			goto cleanup;
	}

	if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
		char hex[3];
		for (DWORD i = 0; i < hashLen; ++i) {
			sprintf_s(hex, "%02x", hash[i]);
			result += hex;
		}
	}

cleanup:
	if (hHash) CryptDestroyHash(hHash);
	if (hProv) CryptReleaseContext(hProv, 0);
	if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	return result;
}
	std::map<std::string, std::array<int, 2> > gNtkrnlMd5OffMap;
#define DRIVER_NAME2 "kldbgdrv"
#include "ntsupp.h"
#define INSTALLBAT_NAME "installandstartdriver"
BOOLEAN
SetupInstallBatName(
	_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
	_In_ ULONG BufferLength
);// SetupDriverName
VOID DisableTargetProcessPPL(DWORD pid);
BOOLEAN
SetupDriverName222(
	_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
	_In_ ULONG BufferLength
); 
#include <ctype.h>

int IsValidHex(const char* str) {
	if (str == NULL || *str == '\0') return 0;

	// Skip optional 0x or 0X
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
		str += 2;

	if (*str == '\0') return 0;

	while (*str) {
		if (!isxdigit((unsigned char)*str))
			return 0;
		str++;
	}
	return 1;
}

/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2021 - 2024
*
*  TITLE:       NTBUILDS.H
*
*  VERSION:     1.25
*
*  DATE:        11 May 2024
*
*  Windows NT builds definition file.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
char* GetFuncModulePath(DWORD64 funcAddr, char *_3bytesOut);
#pragma once
VOID removeKldbgdrv();

// Replace all occurrences of oldStr with newStr in originalStr
char* ReplaceAll(const char* originalStr, const char* oldStr, const char* newStr) {
	const char* pos = originalStr;
	int count = 0;
	size_t oldLen = strlen(oldStr);
	size_t newLen = strlen(newStr);

	// Count how many times oldStr occurs
	while ((pos = strstr(pos, oldStr)) != NULL) {
		count++;
		pos += oldLen;
	}

	// Allocate buffer for new string
	size_t newSize = strlen(originalStr) + count * (newLen - oldLen) + 1;
	char* result = (char*)malloc(newSize);
	if (!result) return NULL;

	char* dest = result;
	pos = originalStr;

	while (*pos) {
		const char* match = strstr(pos, oldStr);
		if (match) {
			size_t bytes = match - pos;
			memcpy(dest, pos, bytes);
			dest += bytes;
			memcpy(dest, newStr, newLen);
			dest += newLen;
			pos = match + oldLen;
		}
		else {
			strcpy(dest, pos);
			break;
		}
	}

	return result;
}

int ReplaceInFile(const char* filePath, const char* oldStr, const char* newStr) {
	FILE* file = fopen(filePath, "rb");
	if (!file) {
		perror("Failed to open file for reading");
		return -1;
	}

	// Get file size
	fseek(file, 0, SEEK_END);
	long fsize = ftell(file);
	fseek(file, 0, SEEK_SET);

	// Read file into memory
	char* buffer = (char*)malloc(fsize + 1);
	if (!buffer) {
		fclose(file);
		return -2;
	}
	fread(buffer, 1, fsize, file);
	buffer[fsize] = '\0';
	fclose(file);

	// Replace text
	char* modified = ReplaceAll(buffer, oldStr, newStr);
	free(buffer);
	if (!modified) return -3;

	// Write modified content back to file
	file = fopen(filePath, "wb");
	if (!file) {
		perror("Failed to open file for writing");
		free(modified);
		return -4;
	}
	fwrite(modified, 1, strlen(modified), file);
	fclose(file);
	free(modified);

	return 0;
}
//
// Defines for Major Windows NT release builds
//
#include <stdlib.h>

typedef struct Node {
	DWORD64 funcAddr;
	char ori3ByteAsmCode[3];
	bool isDisabled;
	char* funcModulePath;
	struct Node* prev;
	struct Node* next;
} Node;
Node* gPreCallbackHead;
Node* gPostCallbackHead;
// Insert at the front
void insert_front(Node** head, DWORD64 funcAddr) {
	Node* new_node = (Node*)malloc(sizeof(Node));
	new_node->funcAddr = funcAddr;
	new_node->prev = NULL;
	new_node->next = *head;

	if (*head != NULL)
		(*head)->prev = new_node;

	*head = new_node;
}

// Delete a node
void delete_node(Node** head, Node* node) {
	if (*head == NULL || node == NULL) return;

	if (*head == node)
		*head = node->next;

	if (node->next != NULL)
		node->next->prev = node->prev;

	if (node->prev != NULL)
		node->prev->next = node->next;

	free(node);
}
 

// Free entire list
void free_list(Node* head) {
	while (head != NULL) {
		Node* next = head->next;
		free(head);
		head = next;
	}
}

/******************************************************************************
*
* Object type versions
*
* ALPC_PORT
* DEVICE_MAP
* DIRECTORY_OBJECT
* DRIVER_EXTENSION
* OBJECT_TYPE
* OBJECT_SYMBOLIC_LINK
* FLT_FILTER
*
*******************************************************************************/
VOID SetPPLOff(DWORD64 pplOff);
VOID ChangeCallbackFunctionToXoreax_eax_ret(DWORD64 funcAddr);
// Structure version from W7 (7600)
#define OBVERSION_ALPCPORT_V1  (1)
// Structure version from W8 (9200)
#define OBVERSION_ALPCPORT_V2  (2)
// Structure version from W8 BLUE (9600)
#define OBVERSION_ALPCPORT_V3  (3)
// Structure version from W10 (10240)
#define OBVERSION_ALPCPORT_V4  (4)

// Structure version from W7 (7600) until W10 RS1
#define OBVERSION_DEVICE_MAP_V1  (1)
// Structure version from W10 RS1 (14393) until W11
#define OBVERSION_DEVICE_MAP_V2  (2)
// Structure version from W11 (22000)
#define OBVERSION_DEVICE_MAP_V3  (3)

// Structure version for W7-W8 BLUE (7600..9600)
#define OBVERSION_DIRECTORY_V1 (1)
// Structure version for W10 (10240..14393)
#define OBVERSION_DIRECTORY_V2 (2)
// Structure version for W10 (15063+)
#define OBVERSION_DIRECTORY_V3 (3)

BOOLEAN
InstallDriver(
	_In_ SC_HANDLE  SchSCManager,
	_In_ LPCTSTR    DriverName,
	_In_ LPCTSTR    ServiceExe
);


BOOLEAN
RemoveDriver(
	_In_ SC_HANDLE  SchSCManager,
	_In_ LPCTSTR    DriverName
);

BOOLEAN
StartDriver(
	_In_ SC_HANDLE  SchSCManager,
	_In_ LPCTSTR    DriverName
);

BOOLEAN
StopDriver(
	_In_ SC_HANDLE  SchSCManager,
	_In_ LPCTSTR    DriverName
);
 
// Public structure
#define OBVERSION_DRIVER_EXTENSION_V1 (1)
// Private, W7 (7600..7601)
#define OBVERSION_DRIVER_EXTENSION_V2 (2)
// Private, W8 (9200)
#define OBVERSION_DRIVER_EXTENSION_V3 (3)
// Private, since W8 BLUE (9600+)
#define OBVERSION_DRIVER_EXTENSION_V4 (4)

// Structure version W7 (7600..7601)
#define OBVERSION_OBJECT_TYPE_V1 (1)
// Structure version W8-W10 (9200..10586)
#define OBVERSION_OBJECT_TYPE_V2 (2)
// Structure version W10RS1 (14393)
#define OBVERSION_OBJECT_TYPE_V3 (3)
// Structure version W10RS2 (15063+)
#define OBVERSION_OBJECT_TYPE_V4 (4)

// Windows 7 RTM
#define NT_WIN7_RTM             7600

// Windows 7 SP1
#define NT_WIN7_SP1             7601

// Windows 8 RTM
#define NT_WIN8_RTM             9200

// Windows 8.1
#define NT_WIN8_BLUE            9600

// Windows 10 TH1
#define NT_WIN10_THRESHOLD1     10240

// Windows 10 TH2
#define NT_WIN10_THRESHOLD2     10586

// Windows 10 RS1
#define NT_WIN10_REDSTONE1      14393

// Windows 10 RS2
#define NT_WIN10_REDSTONE2      15063

// Windows 10 RS3
#define NT_WIN10_REDSTONE3      16299

// Windows 10 RS4
#define NT_WIN10_REDSTONE4      17134

// Windows 10 RS5
#define NT_WIN10_REDSTONE5      17763

// Windows 10 19H1
#define NT_WIN10_19H1           18362

// Windows 10 19H2
#define NT_WIN10_19H2           18363

// Windows 10 20H1
#define NT_WIN10_20H1           19041

// Windows 10 20H2
#define NT_WIN10_20H2           19042

// Windows 10 21H1
#define NT_WIN10_21H1           19043

// Windows 10 21H2
#define NT_WIN10_21H2           19044

// Windows 10 22H2
#define NT_WIN10_22H2           19045

// Windows Server 2022
#define NT_WINSRV_21H1          20348

// Windows 11 21H2
#define NT_WIN11_21H2           22000

// Windows 11 22H2
#define NT_WIN11_22H2           22621

// Windows 11 23H2
#define NT_WIN11_23H2           22631

// Windows 11 Active Development Branch
#define NT_WIN11_24H2           26120 //canary (24H2)
#define NT_WIN11_25H2           26212 //canary (25H2)


bool EnableDebugPrivilege()
{
    HANDLE tokenHandle;
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
    {
        std::cout << "Failed to open process token. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
        std::cout << "Failed to lookup privilege value. Error: " << GetLastError() << std::endl;
        CloseHandle(tokenHandle);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        std::cout << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
        CloseHandle(tokenHandle);
        return false;
    }

    CloseHandle(tokenHandle);
    return true;
}
typedef enum _OBJ_HEADER_INFO_FLAG {
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag = 0x2,
    HeaderHandleInfoFlag = 0x4,
    HeaderQuotaInfoFlag = 0x8,
    HeaderProcessInfoFlag = 0x10
} OBJ_HEADER_INFO_FLAG;
HANDLE gdeviceHandle;
PVOID ObpCopyObjectBasicInfo(
PVOID object,
PVOID ObjectHeaderAddress,
BOOL _bool,
PVOID ObjectHeaderAddr);
void ObQueryNameStringFromAddress(PVOID infoHeaderAddr,
    PUNICODE_STRING NameString);
PVOID ObDumpObjectTypeVersionAware(PVOID objectAddrl, PVOID ptrObjectSize, PVOID ptrObjectVwersion);
PVOID  ObpDumpObjectWithSpecifiedSize(PVOID objectAddrl,
    ULONG objectSize,
    ULONG objectVersion,
    PVOID ptrObjectSize,
    PVOID ptrObjectVwersion);
BYTE ObGetObjectHeaderOffset(
    _In_ BYTE InfoMask,
    _In_ OBJ_HEADER_INFO_FLAG Flag
); BOOL getinfoaddrfromheader(UCHAR InfoMask,
    PVOID ObjectHeaderAddress, PVOID infoHeaderAddr, OBJ_HEADER_INFO_FLAG _HeaderNameInfoFlag);
void readkernelmemory(HANDLE deviceHandle,
    PVOID kerneladdress,
    PVOID structureAddr,ULONG len);
void iths(int num, char* hexStr) {
	\
		int ii = 0;									 \
		while (num > 0) {
			\
				int rem = num % 16;						 \
				if (rem < 10)							 \
					hexStr[ii] = rem + '0';				 \
				else									 \
					hexStr[ii] = rem + 'A' - 10;			 \
					num /= 16;								 \
					ii++;									 \
		}											 \
			hexStr[ii] = '\0';							 \
					int len = ii;								 \
					for (ii = 0; ii < len / 2; ii++) {
						\
							char temp = hexStr[ii];					 \
							hexStr[ii] = hexStr[len - ii - 1];		 \
							hexStr[len - ii - 1] = temp;				 \
					}											 \
}
typedef struct _OBEX_OBJECT_INFORMATION {
    ULONG_PTR HeaderAddress;
    ULONG_PTR ObjectAddress;
    OBJECT_HEADER_QUOTA_INFO ObjectQuotaHeader;
    OBJECT_HEADER ObjectHeader;
} OBEX_OBJECT_INFORMATION, *POBEX_OBJECT_INFORMATION;

PVOID ntsupGetSystemInfoEx(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_opt_ PULONG ReturnLength,
	_In_ PNTSUPMEMALLOC AllocMem,
	_In_ PNTSUPMEMFREE FreeMem
)
{
	PVOID       buffer = NULL;
	ULONG       bufferSize = PAGE_SIZE;
	NTSTATUS    ntStatus;
	ULONG       returnedLength = 0;

	if (ReturnLength)
		*ReturnLength = 0;

	buffer = AllocMem((SIZE_T)bufferSize);
	if (buffer == NULL)
		return NULL;

	while ((ntStatus = NtQuerySystemInformation( // 核心就是这个函数
		SystemInformationClass,
		buffer,
		bufferSize,
		&returnedLength)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		FreeMem(buffer);
		bufferSize <<= 1; // 返回状态标识内存不够  加内存  一直循环  直到加够为止

		if (bufferSize > NTQSI_MAX_BUFFER_LENGTH)
			return NULL;

		buffer = AllocMem((SIZE_T)bufferSize);
	}

	if (ReturnLength)
		*ReturnLength = returnedLength;

	if (NT_SUCCESS(ntStatus)) {
		return buffer;
	}

	if (buffer)
		FreeMem(buffer);

	return NULL;
}

FORCEINLINE BOOL supHeapFreeEx(
	_In_ HANDLE Heap,
	_In_ PVOID Memory
)
{
	BOOL Result;

	Result = RtlFreeHeap(Heap, 0, Memory);
	 

	return Result;
}
HANDLE g_obexHeap;
FORCEINLINE BOOL supHeapFree(
	_In_ PVOID Memory)
{
	return supHeapFreeEx(g_obexHeap, Memory);
}

FORCEINLINE PVOID supHeapAllocEx(
	_In_ HANDLE Heap,
	_In_ SIZE_T Size
)
{
	PVOID Buffer;

#ifdef _DEBUG
	ULONG64 MaxHeapAllocatedBlockSize;
#endif

	Buffer = RtlAllocateHeap(Heap, HEAP_ZERO_MEMORY, Size);
 

	return Buffer;
}

FORCEINLINE PVOID supHeapAlloc(
	_In_ SIZE_T Size)
{
	return supHeapAllocEx(g_obexHeap, Size);
}
PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_opt_ PULONG ReturnLength
)
{
	return ntsupGetSystemInfoEx(  // 这个就是使用未公开的函数获取到当前系统中所有的句柄
		SystemInformationClass,
		ReturnLength,
		(PNTSUPMEMALLOC)supHeapAlloc,
		(PNTSUPMEMFREE)supHeapFree);
}


BOOL supQueryObjectFromHandleEx(
	_In_ PSYSTEM_HANDLE_INFORMATION_EX HandlesDump,
	_In_ HANDLE Object,
	_Out_opt_ ULONG_PTR* Address,
	_Out_opt_ USHORT* TypeIndex
)
{
	USHORT      objectTypeIndex = 0;
	BOOL        bFound = FALSE;
	DWORD       CurrentProcessId = GetCurrentProcessId();
	ULONG_PTR   i, objectAddress = 0;

	for (i = 0; i < HandlesDump->NumberOfHandles; i++) {
		if (HandlesDump->Handles[i].UniqueProcessId == (ULONG_PTR)CurrentProcessId) { // 句柄所属的进程必须是当前进程
			if (HandlesDump->Handles[i].HandleValue == (ULONG_PTR)Object) { // 句柄的值必须和我们前面获取到的\ObjectTypes目录的句柄值相等
				if (Address) {
					objectAddress = (ULONG_PTR)HandlesDump->Handles[i].Object;// 把该句柄的地址取回来  这个光靠用户模式可以完成吗？这个是内核地址
				}
				if (TypeIndex) {
					objectTypeIndex = HandlesDump->Handles[i].ObjectTypeIndex;
				}
				bFound = TRUE;
				break;
			}
		}
	}

	if (Address)
		*Address = objectAddress;
	if (TypeIndex)
		*TypeIndex = objectTypeIndex;

	return bFound;
}

void log_message(const char *format, ...) {
	// Get the current time
	//time_t now = time(NULL);
	//char time_str[40];
	//strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

	// Prepare the variable argument list
	va_list args;
	va_start(args, format);
	printf(format, args);
	// // Print timestamp and message to console
	// //l("[%s] ", time_str);
	// //vprintf(format, args);
	// //l("\n");
	// // char caonima[1000] = { 0 };
	// // sprintf(caonima, format, args);
	// //MessageBoxA(NULL, caonima, "OK", MB_OK);
	// // Write the same message to a log file
	// char ogpath[100] = { 0 };
	// sprintf(ogpath, "C:\\users\\public\\log.txt");
	// FILE *log_file = fopen(ogpath, "a");
	// if (log_file) {
	// 	//fprintf(log_file, "[%s] ", time_str);
	// 	vfprintf(log_file, format, args);
	// 	//fprintf(log_file, "\n");
	// 	fclose(log_file);
	// }

	va_end(args);
}
#define l log_message 
#include <windows.h>
#include <iostream>
#include <sstream>
#include <fstream>
bool ExtractResourceToFile(int resourceId, const std::wstring& outputPath) {
	HRSRC hResource = FindResource(nullptr, MAKEINTRESOURCE(resourceId), RT_RCDATA);
	if (!hResource) {
		l("Failed to find resource. Error: 0x%x\n", GetLastError());
		return false;
	}

	HGLOBAL hLoadedResource = LoadResource(nullptr, hResource);
	if (!hLoadedResource) {
		l("Failed to load resource. Error: 0x%x\n", GetLastError());
		return false;
	}

	void* pResourceData = LockResource(hLoadedResource);
	DWORD resourceSize = SizeofResource(nullptr, hResource);
	if (!pResourceData || resourceSize == 0) {
		l("Failed to lock resource or resource size is zero.");
		return false;
	}

	std::ofstream outFile(outputPath, std::ios::binary);
	if (!outFile) {
		l("Failed to open output file.");
		return false;
	}

	outFile.write(static_cast<const char*>(pResourceData), resourceSize);
	outFile.close();

	return true;
}
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <string>

bool IsProcessRunning(const std::string& processName) {
	bool found = false;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_stricmp(pe.szExeFile, processName.c_str()) == 0) {
				found = true;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return found;
}

bool RelaunchAsAdmin() {
	char szPath[MAX_PATH] = "C:\\users\\public\\winobjex64.exe";  

	SHELLEXECUTEINFOA sei = { sizeof(sei) };
	sei.lpVerb = "open"; // triggers UAC
	sei.lpFile = szPath;
	sei.hwnd = NULL;
	sei.nShow = SW_NORMAL;

	if (!ShellExecuteExA(&sei)) {
		return false; // user probably clicked "No"
	}
	return true;
}

bool IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = NULL;

	// Allocate and initialize a SID for the administrators group
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&NtAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &adminGroup)) {
		CheckTokenMembership(NULL, adminGroup, &isAdmin);
		FreeSid(adminGroup);
	}

	return isAdmin == TRUE;
}

bool FileExists(const char* path) {
	DWORD attr = GetFileAttributesA(path);
	return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}


#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>


BOOLEAN
ManageDriver(
	_In_ LPCTSTR  DriverName,
	_In_ LPCTSTR  ServiceName,
	_In_ USHORT   Function
);

BOOLEAN
SetupDriverName(
	_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
	_In_ ULONG BufferLength
);

char OutputBuffer[200];
char InputBuffer[100];

#include <iostream>

bool IsServiceRunning(const char* serviceName) {
	SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
	if (!hSCManager) {
		std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
		return false;
	}

	SC_HANDLE hService = OpenServiceA(hSCManager, serviceName, SERVICE_QUERY_STATUS);
	if (!hService) {
		//std::cerr << "OpenService failed: " << GetLastError() << std::endl;
		CloseServiceHandle(hSCManager);
		return false;
	}

	SERVICE_STATUS_PROCESS ssp;
	DWORD bytesNeeded;

	BOOL success = QueryServiceStatusEx(
		hService,
		SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&ssp),
		sizeof(ssp),
		&bytesNeeded
	);

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	if (!success) {
		std::cerr << "QueryServiceStatusEx failed: " << GetLastError() << std::endl;
		return false;
	}

	return ssp.dwCurrentState == SERVICE_RUNNING;
}
VOID __cdecl
installDriver2( 
)
{
	// 这里直接调用bat就行了，然后循环检查目标服务是否处于running状态

	char szPath[MAX_PATH] = "C:\\users\\public\\installandstartdriver.bat";
	
	SHELLEXECUTEINFOA sei = { sizeof(sei) };
	sei.lpVerb = "open"; // triggers UAC
	sei.lpFile = szPath;
	sei.hwnd = NULL;
	sei.nShow = SW_NORMAL;

	if (!ShellExecuteExA(&sei)) {
		printf("[-] fatal error occured when calling installandstartdriver.bat\n");
		exit(-1);
		return  ; // user probably clicked "No"
	}
	printf("[*] waiting for driver load...");
	while (!IsServiceRunning("obcallbacktest")){
		
		Sleep(100);
		printf(".");

}
	printf("\n[+] driver loaded\n");
	return;
	HANDLE hDevice;
	BOOL bRc;
	ULONG bytesReturned;
	DWORD errNum = 0;
	TCHAR driverLocation[MAX_PATH];
	 
	//
	// open the device
	//

	if ((hDevice = CreateFileA("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE) {

		errNum = GetLastError();

		if (errNum != ERROR_FILE_NOT_FOUND) {

			printf("CreateFile failed : %d\n", errNum);

			return;
		}

		//
		// The driver is not started yet so let us the install the driver.
		// First setup full path to driver name.
		//

		if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {

			return;
		}

		if (!ManageDriver(DRIVER_NAME,
			driverLocation,
			DRIVER_FUNC_INSTALL
		)) {

			printf("Unable to install driver.\n");

			//
			// Error - remove driver.
			//

			ManageDriver(DRIVER_NAME,
				driverLocation,
				DRIVER_FUNC_REMOVE
			);

			return;
		}
		printf("custom kernel driver is installed and start\n");
		return;
		hDevice = CreateFile("\\\\.\\ObCallbackTest",
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hDevice == INVALID_HANDLE_VALUE) {
			printf("Error: CreatFile Failed : %d\n", GetLastError());
			return;
		}

	}

	//
	// Printing Input & Output buffer pointers and size
	//

//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
//	sizeof(InputBuffer));
//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	//printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));

	bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		&InputBuffer,
		(DWORD)strlen(InputBuffer) + 1,
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl : %d", GetLastError());
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);

	//
	// Performing METHOD_NEITHER
	//

	printf("\nCalling DeviceIoControl METHOD_NEITHER\n");

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_NEITHER");
	memset(OutputBuffer, 0, sizeof(OutputBuffer));

	bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_NEITHER,
		&InputBuffer,
		(DWORD)strlen(InputBuffer) + 1,
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl : %d\n", GetLastError());
		return;

	}

	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);

	//
	// Performing METHOD_IN_DIRECT
	//

	printf("\nCalling DeviceIoControl METHOD_IN_DIRECT\n");

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_IN_DIRECT");
	StringCbCopy(OutputBuffer, sizeof(OutputBuffer),
		"This String is from User Application in OutBuffer; using METHOD_IN_DIRECT");

	bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_IN_DIRECT,
		&InputBuffer,
		(DWORD)strlen(InputBuffer) + 1,
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl : %d", GetLastError());
		return;
	}

	printf("    Number of bytes transfered from OutBuffer: %d\n",
		bytesReturned);

	//
	// Performing METHOD_OUT_DIRECT
	//

	printf("\nCalling DeviceIoControl METHOD_OUT_DIRECT\n");
	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_OUT_DIRECT");
	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_OUT_DIRECT,
		&InputBuffer,
		(DWORD)strlen(InputBuffer) + 1,
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl : %d", GetLastError());
		return;
	}

	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);

	CloseHandle(hDevice);

	//
	// Unload the driver.  Ignore any errors.
	//

	ManageDriver(DRIVER_NAME,
		driverLocation,
		DRIVER_FUNC_REMOVE
	);


	//
	// close the handle to the device.
	//

}

BOOLEAN
ManageDriver(
	_In_ LPCTSTR  DriverName,
	_In_ LPCTSTR  ServiceName,
	_In_ USHORT   Function
)
{

	SC_HANDLE   schSCManager;

	BOOLEAN rCode = TRUE;

	//
	// Insure (somewhat) that the driver and service names are valid.
	//

	if (!DriverName || !ServiceName) {

		printf("Invalid Driver or Service provided to ManageDriver() \n");

		return FALSE;
	}

	//
	// Connect to the Service Control Manager and open the Services database.
	//

	schSCManager = OpenSCManager(NULL,                   // local machine
		NULL,                   // local database
		SC_MANAGER_ALL_ACCESS   // access required
	);

	if (!schSCManager) {

		printf("Open SC Manager failed! Error = %d \n", GetLastError());

		return FALSE;
	}

	//
	// Do the requested function.
	//

	switch (Function) {

	case DRIVER_FUNC_INSTALL:

		//
		// Install the driver service.
		//
		printf("driver name: %s\n", DriverName);
		printf("service name: %s\n", ServiceName);
		if (InstallDriver(schSCManager,
			DriverName,
			ServiceName
		)) {

			//
			// Start the driver service (i.e. start the driver).
			//

			rCode = StartDriver(schSCManager,
				DriverName
			);

		}
		else {

			//
			// Indicate an error.
			//

			rCode = FALSE;
		}

		break;

	case DRIVER_FUNC_REMOVE:

		//
		// Stop the driver.
		//

		StopDriver(schSCManager,
			DriverName
		);

		//
		// Remove the driver service.
		//

		RemoveDriver(schSCManager,
			DriverName
		);

		//
		// Ignore all errors.
		//

		rCode = TRUE;

		break;

	default:

		printf("Unknown ManageDriver() function. \n");

		rCode = FALSE;

		break;
	}

	//
	// Close handle to service control manager.
	//

	if (schSCManager) {

		CloseServiceHandle(schSCManager);
	}

	return rCode;

}   // ManageDriver
VOID initMap() { 
	// 数组的含义
	/*
	eprocess的protect字段偏移
	ethread的StartAddress字段偏移
	*/
	gNtkrnlMd5OffMap.insert({ "aa85bdb213346ed8bb151dfa5524db0e",std::array<int, 2>{0x87a, 0x450} });
}
VOID removeAndInstallKldbgdrv();
int main(int argc, char* argv[])
{
	initMap();
	std::string md5 = GetFileMD5("C:\\windows\\system32\\ntoskrnl.exe");
	auto it = gNtkrnlMd5OffMap.find(md5);
	if (it == gNtkrnlMd5OffMap.end()) {
		printf("[!] I don't have target field offset info of this ntoskrnl version, ntoskrnl.exe md5: %s\n", md5.c_str());
		printf("[!] get target field offset by executing these commands from your kernel debugger:\n\tdt _eprocess protection\n\tdt _ethread StartAddress\n");
		exit(-1);
	}
	gPploff = it->second[0];
	gEhtread_startAddrOff = it->second[1];
	printf("[*] check if we are running as administrator\n");
	if (!IsRunningAsAdmin()) {
		std::cout << "[!] not running as admin, please relaunch from administrator cmd please...\n";
		return 0;
		// if (RelaunchAsAdmin()) {
		// 	return 0; // Relaunched, so exit original
		// }
		// else {
		// 	std::cerr << "Failed to relaunch as admin.\n";
		// 	return 1;
		// }
	}

	std::cout << "[+] we are running from administrator cmd\n";


	printf("[*] remove and install kldbgdrv driver\n");
	removeAndInstallKldbgdrv();










	// char szPath[MAX_PATH] = "C:\\users\\public\\installandstartdriver.bat";
	// if (!FileExists(driverLsoBatPathcation)) {
	// 	printf("[-] you may forget to copy installandstartdriver.bat to target machine's C:\\users\\public\\ folder\n");
	// 	exit(-1);
	// }
	TCHAR driverLsoBatPathcation[MAX_PATH];

	TCHAR driverLsocation222[MAX_PATH];
	SetupDriverName222(driverLsocation222, sizeof(driverLsocation222));
	
	if (!SetupInstallBatName(driverLsoBatPathcation, sizeof(driverLsoBatPathcation))) {

		return 1;
	}
	if (!FileExists(driverLsoBatPathcation)) {
		printf("[-] you may forget to copy installandstartdriver.bat to target machine's C:\\users\\public\\ folder\n");
		exit(-1);
	}
	TCHAR driverLsocation[MAX_PATH];

	if (!SetupDriverName(driverLsocation, sizeof(driverLsocation))) {

		return 1;
	}
	printf("[*] remove custom driver\n");
	ManageDriver(DRIVER_NAME,
		driverLsocation,
		DRIVER_FUNC_REMOVE
	);
	printf("[+] custom driver is succssfully removed\n");
	if (argc > 1)
		return 0;

	ReplaceInFile(driverLsoBatPathcation, "C:\\users\\public\\obcallbacktest.sys", driverLsocation222);


	// 这里直接调用bat就行了，然后循环检查目标服务是否处于running状态

	char szPath[MAX_PATH] = "C:\\users\\public\\installandstartdriver.bat";

	SHELLEXECUTEINFOA sei = { sizeof(sei) };
	sei.lpVerb = "open"; // triggers UAC
	sei.lpFile = driverLsoBatPathcation;
	sei.hwnd = NULL;
	sei.nShow = SW_NORMAL;

	if (!ShellExecuteExA(&sei)) {
		printf("[-] fatal error occured when calling installandstartdriver.bat\n");
		exit(-1);
		 
	}
	printf("[*] waiting for custom driver load...");
	while (!IsServiceRunning("obcallbacktest")) {

		Sleep(100);
		printf(".");

	}
	printf("\n[+] driver loaded\n");
	 


	int pploff = 0;
	// printf("[*] please input Protect field offset of EPROCESS by execute this command in your kernel debugger:\n\tdt _eprocess protection\n");
	// 
	// 
	// char input[64];
	// 
	// printf("[*] enter hex value (with or without 0x): ");
	// if (scanf("%63s", input) != 1) {
	// 	printf("[!] input error\n");
	// 	return 1;
	// }
	// 
	// if (!IsValidHex(input)) {
	// 	printf("[!] invalid hex input\n");
	// 	return 1;
	// }
	// 
	// unsigned int value = (unsigned int)strtoul(input, NULL, 16);
	// printf("[*] hex value: 0x%X (%u decimal)\n", value, value);




//	pploff = value;
	printf("[*] setting ppl offset\n");
	SetPPLOff(gPploff);
	printf("[+] ppl offset set successfully\n");
	ULONG numberOfBytesRead = 0;

	IO_STATUS_BLOCK iost;

	NTSTATUS          ntStatus;
	HANDLE            directoryHandle = NULL;
	OBJECT_ATTRIBUTES objectAttrbutes;
	UNICODE_STRING  DirectoryName;
	UNICODE_STRING  ProceeString;
	WCHAR  DriverName[] = L"\\DosDevices\\kldbgdrv";


	HANDLE deviceHandle = NULL;
	UNICODE_STRING usDeviceLink;
	RtlInitUnicodeString(&usDeviceLink, DriverName);
	OBJECT_ATTRIBUTES obja;
	InitializeObjectAttributes(&obja, &usDeviceLink, OBJ_CASE_INSENSITIVE, NULL, NULL);


	// std::wstring becomePath = L"C:\\users\\public\\123.7z";
	// if (!ExtractResourceToFile(IDR_BECOME, becomePath)) {
	// 	l("Failed to extract winobj plus\n");
	// }
	// std::wstring becomePath2 = L"C:\\users\\public\\7za.exe";
	// if (!ExtractResourceToFile(IDR_BECOME103, becomePath2)) {
	// 	l("Failed to extract 7za.exe\n");
	// }
	// // 这一步执行完成后执行C:\\users\\public\\WinObjEx64.exe即可
	// system("cmd /c C:\\users\\public\\7za.exe x -y -oC:\\users\\public C:\\users\\public\\123.7z");
	// while (IsProcessRunning(L"7za.exe")) {
	// 	Sleep(100);
	// }
	// if (!IsProcessRunning("WinObjEx64.exe")) {
	// 
	// 	if (!FileExists("C:\\users\\public\\WinObjEx64.exe")) {
	// 		printf("put your winobj plus to C:\\users\\public directory\n");
	// 		system("start C:\\users\\public");
	// 		return 0;
	// 	}
	// 	// 执行winobjplus
	// 	RelaunchAsAdmin();
	// 	while (!IsProcessRunning("WinObjEx64.exe")) {
	// 		Sleep(100);
	// 	}
	// 
	// }
	// printf("WinObjEx64.exe is now running\n");
    EnableDebugPrivilege(); // 启用debug权限，不然用不了windbg的那个驱动
	g_obexHeap = HeapCreate(0, 0, 0);
	ntStatus = NtCreateFile(&deviceHandle,
		0xc0000000,
		&obja,
		&iost,
		NULL,
		0,
		0,
		FILE_OPEN,
		0,
		NULL,
		0);
	if (ntStatus != 0) {
		printf("please click Extras->System Callbacks from WinObjEx.exe and then press any key to continue\n");
		system("pause");
	}
	else goto justgo;
	
	while (1) {
		ntStatus = NtCreateFile(&deviceHandle,
			0xc0000000,
			&obja,
			&iost,
			NULL,
			0,
			0,
			FILE_OPEN,
			0,
			NULL,
			0);
		if (ntStatus != 0) {
			printf("please click Extras->System Callbacks from WinObjEx.exe and then relunch this program\n");
			Sleep(1000);
			continue;
		}
		break;
	}

justgo:

    RtlInitUnicodeString(&DirectoryName, L"\\ObjectTypes");
    RtlInitUnicodeString(&ProceeString, L"Process");
	InitializeObjectAttributes(&objectAttrbutes,
		&DirectoryName, OBJ_CASE_INSENSITIVE, 0, NULL);

	ntStatus = NtOpenDirectoryObject(&directoryHandle,  // 传出句柄
		1,// 这里使用的是windows api   渴望权限是  1
		&objectAttrbutes);  // 打开 \ObjectTypes 对象目录的句柄
	DWORD64 _1 = 0;
	
	//printf("0x%08X\n", directoryHandle);// 获取当前系统中所有的句柄
	PSYSTEM_HANDLE_INFORMATION_EX pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);

	BOOL bFound = supQueryObjectFromHandleEx(pHandles, // 从handle数组中寻找我们要的句柄
		directoryHandle, // object是\ObjectTypes目录句柄
		(ULONG_PTR*)&_1,// 这个函数可以获取到我们前面打开的对象目录的句柄的内核地址
		0	);
	//printf("\ObjectTypes Directory object kernel address %p\n", _1);
	 
	PVOID addrObjectTypeDir = reinterpret_cast<PBYTE>(_1);

	//printf("%x\n",  0x10 | 4 | 2 | 1);
	// 使用驱动读取内存
	// 传入内核地址   传出结构体地址   结构体size
	/*
	(DirectoryAddress, // 使用内核驱动读取  内核地址
        &DirectoryObject,  // 取出来 DirectoryObject 对象存到变量里
        sizeof(OBJECT_DIRECTORY)))

		Callbacks.ReadSystemMemory(driverContext,
		Address,
		Buffer,
		BufferSize,
		&numberOfBytesRead);

		ntStatus = NtDeviceIoControlFile(Context->DeviceHandle, // 最终还是通过调用deviceiocontrol来和内核驱动进行通信  内核驱动是kldbgdrv
	NULL,
	NULL,
	NULL,
	&iost,
	IOCTL_KD_PASS_THROUGH,  // iocontrolcode
	&kldbg,
	sizeof(kldbg),
	&dbgRequest,
	sizeof(dbgRequest));
	*/
	
    gdeviceHandle = deviceHandle;

    OBJECT_DIRECTORY DirectoryObject;
    readkernelmemory(deviceHandle, // 使用驱动读取我们刚才获取到的_object_directory结构体的内核地址
        reinterpret_cast<PVOID>(_1),
        &DirectoryObject,sizeof(DirectoryObject));
    

    OBJECT_HEADER ObjectHeader;
    PVOID lpdata = 0;
    UNICODE_STRING NameString;
  //  printf("error code: 0x%x\n", GetLastError()); // 我草泥马不让老子访问？只能你傻逼winobj可以用是吧我操你妈的
    // 不就是读个内存吗  老子自己也会写
    PVOID ObjectHeaderAddress;
    OBJECT_DIRECTORY_ENTRY DirectoryEntry;
    PVOID infoHeaderAddr = 0;
   // 然后需要遍历directoryobject里面的节点
    // 一共37个bucket
    for (int i = 0; i < 37; i++) {// 遍历所有的bucket
        PVOID itemHead = DirectoryObject.HashBuckets[i]; // 取出来单链表的头节点地址
        PVOID lokupHItem = 0;
        if (itemHead) {
            lokupHItem = itemHead;
            do {
                memset(&DirectoryEntry, 0, sizeof(DirectoryEntry));
                readkernelmemory(deviceHandle,
                    lokupHItem, // 读出来头节点
                    &DirectoryEntry,sizeof(DirectoryEntry));
                memset(&ObjectHeader, 0, sizeof(ObjectHeader));
                // 使用 CONTAINING_RECORD 宏来获取objecthread结构体的地址
                ObjectHeaderAddress = OBJECT_TO_OBJECT_HEADER(DirectoryEntry.Object);// 这个object就是目录中objectheader的地址
                readkernelmemory(deviceHandle, ObjectHeaderAddress, &ObjectHeader,sizeof(ObjectHeader));// 读出来objhectheadeder的地址
                // 从header结构体中获取nameinfo结构体的地址  infomask 是用来获取可选HEADER的地址的  一共有5个可选header，最后一个参数表示了想要的是哪个可选header
                getinfoaddrfromheader(ObjectHeader.InfoMask, ObjectHeaderAddress, &
                    infoHeaderAddr, HeaderNameInfoFlag);
                // 然后查询名字看是不是Process  如果是Process的话就返回
                ObQueryNameStringFromAddress(infoHeaderAddr, &NameString);// 拿到地址之后我们需要看一下这个ObjectHeader的名称，拿到之后和Process这个字符串进行比较，我们就可以知道这个Object是不是一个Process对象了
              //  wprintf(L"%s\n", NameString.Buffer);// ")
                if (RtlEqualUnicodeString(&ProceeString, &NameString, TRUE)) {
                    // 拷贝信息   找到正确的对象之后，需要拷贝一些必要的信息出来
                 lpdata=   ObpCopyObjectBasicInfo(
                        (PVOID)DirectoryEntry.Object,
                        ObjectHeaderAddress,
                        TRUE,
                        &ObjectHeader);
                 goto breakout;
                }
                lokupHItem = ((OBJECT_DIRECTORY_ENTRY*)&DirectoryEntry)->ChainLink;// 每个bucket都是一个单向链表
            } while (lokupHItem);

        }
    }
breakout:
    int caonima = 0;
    PVOID objectAddrl =(PVOID) ((POBEX_OBJECT_INFORMATION)lpdata)->ObjectAddress; // 拿到对象的地址
    ULONG ObjectSize ,ObjectVwersion= 0;
   PVOID objectTypeINfo= ObDumpObjectTypeVersionAware(objectAddrl, &ObjectSize, &ObjectVwersion);



    union {
        union {
            OBJECT_TYPE_7* ObjectType_7;
            OBJECT_TYPE_8* ObjectType_8;
            OBJECT_TYPE_RS1* ObjectType_RS1;
            OBJECT_TYPE_RS2* ObjectType_RS2;
        } Versions;
        PVOID Ref;
    } ObjectType;
    ULONG_PTR ListHead = 0;
    ULONG CallbackListOffset = 0;
    ObjectType.Ref = objectTypeINfo; // 这个objecttypeinfo其实就是object本身了
    if (ObjectType.Versions.ObjectType_7->TypeInfo.SupportsObjectCallbacks) {// 这个字段决定了这个对象是否支持回调操作 

        switch (ObjectVwersion) {
        case OBVERSION_OBJECT_TYPE_V1:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_7, CallbackList);
            break;

        case OBVERSION_OBJECT_TYPE_V2:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_8, CallbackList);
            break;

        case OBVERSION_OBJECT_TYPE_V3:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS1, CallbackList);
            break;

        default:
            CallbackListOffset = FIELD_OFFSET(OBJECT_TYPE_RS2, CallbackList);// 回调链表的头节点  因为这些对象是在ObjectType目录下的，所以这些对象都是ObjectType类型的？ 好像还真就是这么回事  nt!_OBJECT_TYPE   这里获取到CallbacklIst字段在objecttype结构体中的偏移量
            break;
        }
        ListHead = ((POBEX_OBJECT_INFORMATION)lpdata)->ObjectAddress + CallbackListOffset;// 取出链表entry的地址
    }
    //printf("\n\n\n=======================================================\nProcesssType callback list head adrr: 0x%p\n", ListHead);
    // ListHead就是 就是个什么东西说实话我也说不上来  我已经迷失在代码的海洋里了
    // 趁着还没有迷得太深，我得回顾一下
    // objecttype对象目录下的所有对象都是nt!_object_type类型的，但是他们每个人都有不同的名称，我们要找的就是名称为Process的  在这里面我们可以找到Process类型的Object相关的callback   最终我们可以找到callbacklist链表的一个entry

    // 有了callbacklist链表的entry地址之后，我们就可以遍历callback了
    // 初始化一个链表用来存放我们dump下来的callback信息

    OB_CALLBACK_CONTEXT_BLOCK CallbackEntry;
    LIST_ENTRY ListEntry;
    ListEntry.Flink = ListEntry.Blink = NULL;
    readkernelmemory(deviceHandle, reinterpret_cast<PVOID>(ListHead), &ListEntry, sizeof(ListEntry));

    while (reinterpret_cast<PVOID>( ListEntry .Flink) != reinterpret_cast<PVOID>(ListHead) ){
       // printf("current callbacklist node addr: 0x%p\n", ListEntry.Flink);
        memset(&CallbackEntry, 0, sizeof(CallbackEntry));

        // 获取CallbackEntry结构体
        readkernelmemory(deviceHandle, ListEntry.Flink, &CallbackEntry, sizeof(CallbackEntry));

       // 这里就可以获取到precallback和postcallback函数的地址了
		if (CallbackEntry.PreCallback) {
		//	printf("\tPRE callback addr: 0x%p\n", CallbackEntry.PreCallback);
			//ChangeCallbackFunctionToXoreax_eax_ret((DWORD64)CallbackEntry.PreCallback);
		 
				insert_front(&gPreCallbackHead, (DWORD64)CallbackEntry.PreCallback);
		}
		if (CallbackEntry.PostCallback) {
			//printf("\tPOST callback addr: 0x%p\n", CallbackEntry.PostCallback);
			// ChangeCallbackFunctionToXoreax_eax_ret((DWORD64)CallbackEntry.PostCallback);
			insert_front(&gPostCallbackHead, (DWORD64)CallbackEntry.PreCallback);
		}
        ListEntry.Flink = CallbackEntry.CallbackListEntry.Flink;
//printf("\n");
    }

	while (1) {
	
	
		// 遍历callback，获取对应路径

		Node* temp = gPreCallbackHead;
		while (temp != NULL) {
			temp->funcModulePath = GetFuncModulePath(temp->funcAddr,temp->ori3ByteAsmCode);
			temp = temp->next;
		}
		temp = gPostCallbackHead;
		while (temp != NULL) {
			temp->funcModulePath = GetFuncModulePath(temp->funcAddr, temp->ori3ByteAsmCode);
			temp = temp->next;
		}
		

		break;

	}



	while (1) {
		printf("1. disable target process PPL protection\n");
		printf("2. disable object pre/post callback\n");
		printf("3. enable object pre/post callback\n");
		printf("4. debug target process from the beginning\n");
		printf("5. resume all sleep thread of debugged process\n");
		int opt = 0;
		printf("please input option number, enter b to go back:\n> ");
		char optStr[100] = { 0 };
		scanf("%s",&optStr);
		if (!strcmp(optStr, "b")) {
			printf("heading back\n");
			break;
		}
		opt = atoi(optStr);
		switch (opt)
		{
		case 1: {
			printf("process that enabled ppl protection:\n");
			// 展示所有开启了PPL的进程
			displaypplprocess();
			DWORD pid = 0;
			printf("please input target process pid:\n");
			scanf("%d", &pid);
			DisableTargetProcessPPL(pid);
			printf("target process's ppl protection is disabled\n");
			break;
		}
		
		case 2: {
			int index = 1;
			// 打印一下
			Node* 	temp = gPreCallbackHead;
			printf("PRE callback function address and corresponding module path\n");
		 
			while (temp != NULL) {
				if (!temp->isDisabled)
					printf("[*] ");
				else
					printf("[ ] ");
				printf("%d.\t0x%p\t%s\n", index++, temp->funcAddr, temp->funcModulePath);
				temp = temp->next;
			}
			temp = gPostCallbackHead;
			printf("POST callback function address and corresponding module path\n");
			while (temp != NULL) {
				if (!temp->isDisabled)
					printf("[*] ");
				else
					printf("[ ] ");
				printf("%d.\t0x%p\t%s\n", index++, temp->funcAddr, temp->funcModulePath);
				temp = temp->next;
			}
			printf("input the index number of the target callback that you want to disable, enter 0 to disable all\n");
			char indexNumStr[100] = { 0 };
			int indexNum = 0;
			scanf("%s", &indexNumStr);
			if (!strcmp(indexNumStr, "b")) {
				printf("heading back\n");
				break;
			}
			indexNum = atoi(indexNumStr);
			if (indexNum > index-1) {
				printf("[!] exceed maxmium index, heading back\n");
				break;
			}
			if (!indexNum) {
				temp = gPreCallbackHead;
				while (temp != NULL) {
					ChangeCallbackFunctionToXoreax_eax_ret(temp->funcAddr);
					temp->isDisabled = 1;
					temp = temp->next;
				}
				temp = gPostCallbackHead;
				while (temp != NULL) {
					ChangeCallbackFunctionToXoreax_eax_ret(temp->funcAddr);
					temp->isDisabled = 1;
					temp = temp->next;
				}
			}
			else {
				temp = gPreCallbackHead;
				index = 1;
				while (temp != NULL) {
					if (index == indexNum) {
						ChangeCallbackFunctionToXoreax_eax_ret(temp->funcAddr);
						temp->isDisabled = 1;
					}
					index++;
					temp = temp->next;
				}
				temp = gPostCallbackHead;
				while (temp != NULL) {
					if (index == indexNum) {
						ChangeCallbackFunctionToXoreax_eax_ret(temp->funcAddr);
						temp->isDisabled = 1;
					}
					index++;
					temp = temp->next;
				}
			}
			printf("[+] target pre/post callback is disabled\n");
			break;
		}
		case 3: {

			Node* 	temp = gPreCallbackHead;

			while (temp != NULL) {
				if (temp->isDisabled) {

					RestoreObjCallback(temp->funcAddr, temp->ori3ByteAsmCode);
					temp->isDisabled = 0;
				}
				temp = temp->next;
			}
			temp = gPostCallbackHead;
			while (temp != NULL) {
				if (temp->isDisabled) {

					RestoreObjCallback(temp->funcAddr, temp->ori3ByteAsmCode);
					temp->isDisabled = 0;
				}
				temp = temp->next;
			}
			printf("[+] all object pre/post callback function is enabled\n");
			break;
		}
		case 4: {
			char processname[MAX_PATH] = { 0 };
			printf("please input target process id: \n");
			scanf("%s", &processname);
			if (!strcmp(processname, "b")) {
				printf("heading back\n");
				break;
			}
			int pid = atoi(processname);
			if (!CheckIfPidExist(pid, 0)) {
				printf("[!] no such pid, check your input\n");
				break;
			}
			memset(processname, 0, sizeof(processname));
			GetNameByPID(pid, processname);
			// 先关闭目标进程的PPL

			DisableTargetProcessPPL(pid);
			// 设置目标进程名称
			SetTargetProcessName(processname);
			printf("[+] target process name set in kernel successfully\n");
			memset(processname, 0, sizeof(processname));
			GetProcessPathByPid(pid, processname); 
			printf("[*] target process full path: \n\t%s\n", processname);
			BYTE entryRoutine[preSetEntryRoutineHeadBytesCount] = { 0 };
			std::vector<BYTE> entryBytes;
			int entryOff = GetPEEntryPointBytes(processname, entryBytes);
			printf("[*] original first bytes of target PE entry point: 0x%02x\n", entryBytes[0]);
			SetFullPathInKernel(processname);
			ExtractDir(processname);
			printf("[*] target process installation folder: \n\t%s\n", processname);
			SetTargetProcessFolderPath(processname);
			
			SetEntryPointOffsetOfTargetProcess(entryOff);
			// if (GetPEEntryPointBytes(processname, entryBytes)) {
			// //	std::cout << "Entry Point First 0x10 Bytes: ";
			// 	int i = 0;
			// 	printf("[*] first 0x%x bytes original machine code of RtlUserThreadStart function:\n", preSetEntryRoutineHeadBytesCount);
			// 	for (BYTE b : entryBytes) {
			// 		printf("0x%02X ", b);
			// 		entryRoutine[i++] = b;
			// 	}
		 	// std::cout << "\n";
			// }
			SetEntryRoutineHeadBytes((char*)entryRoutine);
			// printf("[+] entry point head bytes set in kernel successfully\n");
			// 杀死进程
			TerminateTargetProcess(pid);
			printf("[*] waiting for target process to be terminated.");
			int a = 0;
			while (!a) {
				
				printf(".");
				Sleep(500);
				a = AskKernelIfTargetProcessIsCrashed();
			}
			printf("\n[+] target process is terminated successfully\n");
			printf("[*] new process id is %d, you can attach to it now\n", a);
			break;
		}
		case 5: {
			ResumeSleepThread();
			
			break; }
		default:
			printf("option not support\n");
			break;
		}
	
	}













	printf("[*] remove kldbgdrv driver\n");
	removeKldbgdrv();



	printf("[*] remove custom driver\n");
	ManageDriver(DRIVER_NAME,
		driverLsocation,
		DRIVER_FUNC_REMOVE
	);
	printf("[+] custom driver is succssfully removed\n");
	return 0;
}
PVOID
ObDumpObjectTypeVersionAware(PVOID objectAddrl, PVOID ptrObjectSize, PVOID ptrObjectVwersion) {

    RTL_OSVERSIONINFOW osver;
    RtlGetVersion(&osver);

    ULONG  g_NtBuildNumber = osver.dwBuildNumber;
    ULONG objectSize = 0;
    ULONG objectVersion = 0;

    switch (g_NtBuildNumber) {
    case NT_WIN7_RTM:
    case NT_WIN7_SP1:
        objectSize = sizeof(OBJECT_TYPE_7);
        objectVersion = OBVERSION_OBJECT_TYPE_V1;
        break;
    case NT_WIN8_RTM:
    case NT_WIN8_BLUE:
    case NT_WIN10_THRESHOLD1:
    case NT_WIN10_THRESHOLD2:
        objectSize = sizeof(OBJECT_TYPE_8);
        objectVersion = OBVERSION_OBJECT_TYPE_V2;
        break;
    case NT_WIN10_REDSTONE1:
        objectSize = sizeof(OBJECT_TYPE_RS1);
        objectVersion = OBVERSION_OBJECT_TYPE_V3;
        break;
    default:
        objectSize = sizeof(OBJECT_TYPE_RS2);
        objectVersion = OBVERSION_OBJECT_TYPE_V4;
        break;
    }

    LPVOID objectTypeINfo = ObpDumpObjectWithSpecifiedSize(objectAddrl,
        objectSize,
        objectVersion,
        ptrObjectSize,
        ptrObjectVwersion);
    return objectTypeINfo;


}
#ifndef ALIGN_UP_BY
#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#endif
PVOID  ObpDumpObjectWithSpecifiedSize(PVOID objectAddrl,
    ULONG objectSize,
    ULONG objectVersion,
    PVOID ptrObjectSize,
    PVOID ptrObjectVwersion) {
    // 我们需要对这个size进行一下向上对齐的操作

    ULONG BufferSize = ALIGN_UP_BY(objectSize, PAGE_SIZE);
    PVOID objectBUffer = malloc(BufferSize);
    // 不过真正读取的时候用的还是对齐前的内存大小
    readkernelmemory(gdeviceHandle, objectAddrl, objectBUffer, objectSize);
    *(ULONG*)ptrObjectVwersion = objectVersion;

        *(ULONG*)ptrObjectSize = objectSize;
    return objectBUffer;

} 
     
PVOID ObpCopyObjectBasicInfo(
    PVOID object,
    PVOID ObjectHeaderAddress,
    BOOL _bool,
    PVOID ObjectHeaderAddr) {


    POBEX_OBJECT_INFORMATION   lpData = (POBEX_OBJECT_INFORMATION)malloc(sizeof(OBEX_OBJECT_INFORMATION)); // 自定义的结构体，用于存储一些必要的信息

    ULONG_PTR HeaderAddress = 0, InfoHeaderAddress = 0;
    // 保存一些数据
    // 保存对象地址
    lpData->ObjectAddress = (ULONG_PTR)object;
    lpData->HeaderAddress = (ULONG_PTR)ObjectHeaderAddress;

    // 把我们从内核里面读取出来的objectHeader结构体整个复制一份
    memcpy(&lpData->ObjectHeader, ObjectHeaderAddr, sizeof(OBJECT_HEADER));

    // 还有一个什么quotainfo  我没弄懂这个东西是干嘛的
   
   if( getinfoaddrfromheader((*(OBJECT_HEADER*)ObjectHeaderAddr).InfoMask,
        ObjectHeaderAddress, &InfoHeaderAddress, HeaderQuotaInfoFlag))// 这里在获取另一个可选Header的地址，ObjectHeaderQuotaInfo
    memcpy(&lpData->ObjectQuotaHeader, &InfoHeaderAddress, sizeof(OBJECT_HEADER_QUOTA_INFO)); // 成功的话就把这个可选Header的数据也拷贝出来
   return lpData;
}
void ObQueryNameStringFromAddress(PVOID infoHeaderAddr,
    PUNICODE_STRING NameString ) {
    PVOID NameInfoAddress;
    LPWSTR objectName = NULL;
    OBJECT_HEADER_NAME_INFO nameInfo;
    memset(&nameInfo, 0, sizeof(nameInfo));
    readkernelmemory(gdeviceHandle, infoHeaderAddr, &nameInfo, sizeof(nameInfo));
    if (nameInfo.Name.Length ) {

        ULONG allocLength = nameInfo.Name.Length;
        objectName = (LPWSTR)malloc(allocLength + sizeof(UNICODE_NULL));
        memset(objectName, 0, allocLength + sizeof(UNICODE_NULL));//)
        // objectName = (LPWSTR)supHeapAllocEx(HeapHandle,
          //  allocLength + sizeof(UNICODE_NULL);

        if (objectName != NULL) {

            NameInfoAddress = (PVOID)nameInfo.Name.Buffer;

          readkernelmemory(gdeviceHandle, NameInfoAddress,
                objectName,
                nameInfo.Name.Length);
         
                NameString->Buffer = objectName;
                NameString->Length = nameInfo.Name.Length;
                NameString->MaximumLength = nameInfo.Name.MaximumLength;

           
            

        }
    }


}
BYTE ObGetObjectHeaderOffset(
    _In_ BYTE InfoMask,
    _In_ OBJ_HEADER_INFO_FLAG Flag
)
{
    BYTE OffsetMask, HeaderOffset = 0;

    if ((InfoMask & Flag) == 0)
        return 0;

    OffsetMask = InfoMask & (Flag | (Flag - 1));

    if ((OffsetMask & HeaderCreatorInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_CREATOR_INFO);

    if ((OffsetMask & HeaderNameInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);

    if ((OffsetMask & HeaderHandleInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_HANDLE_INFO);

    if ((OffsetMask & HeaderQuotaInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_QUOTA_INFO);

    if ((OffsetMask & HeaderProcessInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_PROCESS_INFO);
    
    return HeaderOffset;
}

BOOL getinfoaddrfromheader(UCHAR InfoMask,
    PVOID ObjectHeaderAddress, PVOID infoHeaderAddr, OBJ_HEADER_INFO_FLAG _HeaderNameInfoFlag) {
    ULONG headOffset = ObGetObjectHeaderOffset(InfoMask, _HeaderNameInfoFlag); // 这里获取可选HEADER的偏移量  关于可选header的便宜计算 可以参考文章 https://codemachine.com/articles/object_headers.html 另外在该代码配套的笔记中也有所记录  winobj源码阅读笔记
    if (headOffset == 0)
        return FALSE;
    PVOID addr = reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(ObjectHeaderAddress) - headOffset
    );
    *(DWORD64*)infoHeaderAddr = reinterpret_cast<DWORD64>(addr); // 获取到可选header的地址 根据该函数的最后一个参数可知  该可选Header是 OBJECT_HEADER_NAME_INFO

}
void readkernelmemory(HANDLE deviceHandle,
    PVOID kerneladdress,
    PVOID structureAddr,ULONG len = 0) {
    ULONG _len = 0;
  _len = len;
    
    IO_STATUS_BLOCK iost;
    typedef struct _KLDBG {
        SYSDBG_COMMAND SysDbgRequest;
        PVOID Buffer;
        DWORD BufferSize;
    }KLDBG, *PKLDBG;
    KLDBG           kldbg;
    SYSDBG_VIRTUAL  dbgRequest;
    kldbg.SysDbgRequest = SysDbgReadVirtual;
    kldbg.Buffer = &dbgRequest;
    kldbg.BufferSize = sizeof(SYSDBG_VIRTUAL);
    OBJECT_DIRECTORY DirectoryObject;
    dbgRequest.Address = kerneladdress;
    dbgRequest.Buffer = structureAddr;
    dbgRequest.Request = _len;
    memset(structureAddr, 0, _len);
    //
    // printf("%d\n", DeviceIoControl(deviceHandle,  /**   IOCTL_KD_PASS_THROUGH   */0x22C007, &kldbg, sizeof(kldbg), &dbgRequest, sizeof(dbgRequest), &numberOfBytesRead, 0));
    // 这里应该封装成函数，不然这样写太麻烦了
    NTSTATUS   ntStatus = NtDeviceIoControlFile(deviceHandle, // 最终还是通过调用deviceiocontrol来和内核驱动进行通信  内核驱动是kldbgdrv
        NULL,
        NULL,
        NULL,
        &iost,
        0x22C007,  // iocontrolcode
        &kldbg,
        sizeof(kldbg),
        &dbgRequest,
        sizeof(dbgRequest));
}



BOOLEAN
SetupDriverName(
	_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
	_In_ ULONG BufferLength
)
{
	HANDLE fileHandle;
	DWORD driverLocLen = 0;

	//
	// Get the current directory.
	//

	driverLocLen = GetCurrentDirectory(BufferLength,
		DriverLocation
	);

	if (driverLocLen == 0) {

		printf("GetCurrentDirectory failed!  Error = %d \n", GetLastError());

		return FALSE;
	}
	//
	// Setup path name to driver file.
	//
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, BufferLength, "\\"DRIVER_NAME".sys"))) {
		return FALSE;
	}

	//
	// Insure driver file is in the specified directory.
	//

	char fullPath[MAX_PATH] = { 0 };
	memset(DriverLocation, 0, sizeof(DriverLocation));
	GetModuleFileNameA(NULL, DriverLocation, MAX_PATH);

	// Strip off the executable name to get just the directory
	char* lastSlash = strrchr(DriverLocation, '\\');
	if (lastSlash) {
		*lastSlash = '\0'; // terminate the string at the last backslash
	}
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, MAX_PATH, "\\"DRIVER_NAME".sys"))) {
		return FALSE;
	}
	//printf("driver location: %s\n", DriverLocation);
	if ((fileHandle = CreateFile(DriverLocation,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {


		printf("%s.sys is not loaded.\n", DRIVER_NAME);

		//
		// Indicate failure.
		//

		return FALSE;
	}

	//
	// Close open file handle.
	//

	if (fileHandle) {

		CloseHandle(fileHandle);
	}

	//
	// Indicate success.
	//

	return TRUE;


}   // SetupDriverName
VOID RestoreObjCallback(DWORD64 funcAddr, char* _3bytes) {
	 
		Msg* msg = (Msg*)malloc(sizeof(Msg));
		memset(msg, 0, sizeof(Msg));
		msg->cmdType = enum_RestoreObjectCallback;
		msg->a1 = funcAddr;
		memcpy(&msg->a2, _3bytes, 3);


		HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hDevice == INVALID_HANDLE_VALUE) {
			printf("can't open custom kernel driver, error code: %d\n", GetLastError());
			return;
		}

		//
		// Printing Input & Output buffer pointers and size
		//

		//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
		//	sizeof(InputBuffer));
		//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
		//	sizeof(OutputBuffer));
		//
		// Performing METHOD_BUFFERED
		//

		StringCbCopy(InputBuffer, sizeof(InputBuffer),
			"This String is from User Application; using METHOD_BUFFERED");

		// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

		memset(OutputBuffer, 0, sizeof(OutputBuffer));
		DWORD bytesReturned = 0;
		bool bRc = DeviceIoControl(hDevice,
			(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
			msg,
			sizeof(Msg),
			&OutputBuffer,
			sizeof(OutputBuffer),
			&bytesReturned,
			NULL
		);

		if (!bRc)
		{
			printf("Error in DeviceIoControl from function DisableTargetProcessPPL: %d", GetLastError());
			free(msg);
			CloseHandle(hDevice);
			return;

		}
		//int ret = 0;
		//if (12138 == bytesReturned) {
		//	ret = 1;
		//}
		////printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
		free(msg);
		CloseHandle(hDevice);
		return ;
	}
int CheckProcessPPL(DWORD pid) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_CheckPPL;
	msg->a1 = pid;


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return 0;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function DisableTargetProcessPPL: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return 0;

	}
	int ret = 0;
	if (12138 == *(DWORD*)OutputBuffer) {
		ret = 1;
	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
	return ret;
}
VOID DisableTargetProcessPPL(DWORD pid) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_DisablePPL;
	msg->a1 = pid;


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function DisableTargetProcessPPL: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}
BOOLEAN
SetupDriverName222(
	_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
	_In_ ULONG BufferLength
)
{
	HANDLE fileHandle;
	DWORD driverLocLen = 0;

	//
	// Get the current directory.
	//

	driverLocLen = GetCurrentDirectory(BufferLength,
		DriverLocation
	);

	if (driverLocLen == 0) {

		printf("GetCurrentDirectory failed!  Error = %d \n", GetLastError());

		return FALSE;
	}
	//
	// Setup path name to driver file.
	//
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, BufferLength, "\\"DRIVER_NAME".inf"))) {
		return FALSE;
	}

	//
	// Insure driver file is in the specified directory.
	//

	char fullPath[MAX_PATH] = { 0 };
	memset(DriverLocation, 0, sizeof(DriverLocation));
	GetModuleFileNameA(NULL, DriverLocation, MAX_PATH);

	// Strip off the executable name to get just the directory
	char* lastSlash = strrchr(DriverLocation, '\\');
	if (lastSlash) {
		*lastSlash = '\0'; // terminate the string at the last backslash
	}
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, MAX_PATH, "\\"DRIVER_NAME".inf"))) {
		return FALSE;
	}
	 printf("[*] custom driver install file location: %s\n", DriverLocation);
	if ((fileHandle = CreateFile(DriverLocation,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {


		printf("%s.sys is not loaded.\n", DRIVER_NAME);

		//
		// Indicate failure.
		//

		return FALSE;
	}

	//
	// Close open file handle.
	//

	if (fileHandle) {

		CloseHandle(fileHandle);
	}

	//
	// Indicate success.
	//

	return TRUE;


}   // SetupDriverName
BOOLEAN
SetupInstallBatName(
	_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
	_In_ ULONG BufferLength
)
{
	HANDLE fileHandle;
	DWORD driverLocLen = 0;

	//
	// Get the current directory.
	//

	driverLocLen = GetCurrentDirectory(BufferLength,
		DriverLocation
	);

	if (driverLocLen == 0) {

		printf("GetCurrentDirectory failed!  Error = %d \n", GetLastError());

		return FALSE;
	}
	//
	// Setup path name to driver file.
	//
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, BufferLength, "\\"INSTALLBAT_NAME".bat"))) {
		return FALSE;
	}

	//
	// Insure driver file is in the specified directory.
	//

	char fullPath[MAX_PATH] = { 0 };
	memset(DriverLocation, 0, sizeof(DriverLocation));
	GetModuleFileNameA(NULL, DriverLocation, MAX_PATH);

	// Strip off the executable name to get just the directory
	char* lastSlash = strrchr(DriverLocation, '\\');
	if (lastSlash) {
		*lastSlash = '\0'; // terminate the string at the last backslash
	}
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, MAX_PATH, "\\"INSTALLBAT_NAME".bat"))) {
		return FALSE;
	}
	printf("[*] custom driver install bat location: %s\n", DriverLocation);
	if ((fileHandle = CreateFile(DriverLocation,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {


		printf("%s.sys is not loaded.\n", DRIVER_NAME);

		//
		// Indicate failure.
		//

		return FALSE;
	}

	//
	// Close open file handle.
	//

	if (fileHandle) {

		CloseHandle(fileHandle);
	}

	//
	// Indicate success.
	//

	return TRUE;


}   // SetupDriverName




BOOLEAN
InstallDriver(
	_In_ SC_HANDLE  SchSCManager,
	_In_ LPCTSTR    DriverName,
	_In_ LPCTSTR    ServiceExe
)
/*++

Routine Description:

Arguments:

Return Value:

--*/
{
	SC_HANDLE   schService;
	DWORD       err;

	//
	// NOTE: This creates an entry for a standalone driver. If this
	//       is modified for use with a driver that requires a Tag,
	//       Group, and/or Dependencies, it may be necessary to
	//       query the registry for existing driver information
	//       (in order to determine a unique Tag, etc.).
	//

	//
	// Create a new a service object.
	//

	schService = CreateService(SchSCManager,           // handle of service control manager database
		DriverName,             // address of name of service to start
		DriverName,             // address of display name
		SERVICE_ALL_ACCESS,     // type of access to service
		SERVICE_KERNEL_DRIVER,  // type of service
		SERVICE_DEMAND_START,   // when to start service
		SERVICE_ERROR_NORMAL,   // severity if service fails to start
		ServiceExe,             // address of name of binary file
		NULL,                   // service does not belong to a group
		NULL,                   // no tag requested
		NULL,                   // no dependency names
		NULL,                   // use LocalSystem account
		NULL                    // no password for service account
	);

	if (schService == NULL) {

		err = GetLastError();

		if (err == ERROR_SERVICE_EXISTS) {

			//
			// Ignore this error.
			//

			return TRUE;

		}
		else {

			printf("CreateService failed!  Error = %d \n", err);

			//
			// Indicate an error.
			//

			return  FALSE;
		}
	}

	//
	// Close the service object.
	//

	if (schService) {

		CloseServiceHandle(schService);
	}

	//
	// Indicate success.
	//

	return TRUE;

}   // InstallDriver


BOOLEAN
StartDriver(
	_In_ SC_HANDLE    SchSCManager,
	_In_ LPCTSTR      DriverName
)
{
	SC_HANDLE   schService;
	DWORD       err;

	//
	// Open the handle to the existing service.
	//

	schService = OpenService(SchSCManager,
		DriverName,
		SERVICE_ALL_ACCESS
	);

	if (schService == NULL) {

		//printf("OpenService failed!  Error = %d \n", GetLastError());

		//
		// Indicate failure.
		//

		return FALSE;
	}

	//
	// Start the execution of the service (i.e. start the driver).
	//

	if (!StartService(schService,     // service identifier
		0,              // number of arguments
		NULL            // pointer to arguments
	)) {

		err = GetLastError();

		if (err == ERROR_SERVICE_ALREADY_RUNNING) {

			//
			// Ignore this error.
			//

			return TRUE;

		}
		else {

			printf("StartService failure! Error = %d \n", err);

			//
			// Indicate failure.  Fall through to properly close the service handle.
			//

			return FALSE;
		}

	}

	//
	// Close the service object.
	//

	if (schService) {

		CloseServiceHandle(schService);
	}

	return TRUE;

}   // StartDriver




BOOLEAN
StopDriver(
	_In_ SC_HANDLE    SchSCManager,
	_In_ LPCTSTR      DriverName
)
{
	BOOLEAN         rCode = TRUE;
	SC_HANDLE       schService;
	SERVICE_STATUS  serviceStatus;

	//
	// Open the handle to the existing service.
	//

	schService = OpenService(SchSCManager,
		DriverName,
		SERVICE_ALL_ACCESS
	);

	if (schService == NULL) {

	//	printf("OpenService failed!  Error = %d \n", GetLastError());

		return FALSE;
	}

	//
	// Request that the service stop.
	//

	if (ControlService(schService,
		SERVICE_CONTROL_STOP,
		&serviceStatus
	)) {

		//
		// Indicate success.
		//

		rCode = TRUE;

	}
	else {

		printf("ControlService failed!  Error = %d \n", GetLastError());

		//
		// Indicate failure.  Fall through to properly close the service handle.
		//

		rCode = FALSE;
	}

	//
	// Close the service object.
	//

	if (schService) {

		CloseServiceHandle(schService);
	}

	return rCode;

}   //  StopDriver



BOOLEAN
RemoveDriver(
	_In_ SC_HANDLE    SchSCManager,
	_In_ LPCTSTR      DriverName
)
{
	SC_HANDLE   schService;
	BOOLEAN     rCode;

	//
	// Open the handle to the existing service.
	//

	schService = OpenService(SchSCManager,
		DriverName,
		SERVICE_ALL_ACCESS
	);

	if (schService == NULL) {

//		printf("OpenService failed!  Error = %d \n", GetLastError());

		//
		// Indicate error.
		//

		return FALSE;
	}

	//
	// Mark the service for deletion from the service control manager database.
	//

	if (DeleteService(schService)) {

		//
		// Indicate success.
		//

		rCode = TRUE;

	}
	else {

		printf("DeleteService failed!  Error = %d \n", GetLastError());

		//
		// Indicate failure.  Fall through to properly close the service handle.
		//

		rCode = FALSE;
	}

	//
	// Close the service object.
	//

	if (schService) {

		CloseServiceHandle(schService);
	}

	return rCode;

}   // RemoveDriver
int AskKernelIfTargetProcessIsCrashed() {

	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_AskKernelIfTargetProcessIsCrashed;


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return 0;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return 0;

	}

	free(msg);
	CloseHandle(hDevice);
	//printf("[DBG] *(DWORD*)OutputBuffer: 0x%x\n", *(DWORD*)OutputBuffer);
		return *(DWORD*)OutputBuffer;
}
VOID ResumeSleepThread() {

	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_StopThreadCreateSleep;
	 
  
	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	 
	free(msg);
	CloseHandle(hDevice);
}

VOID TerminateTargetProcess(int pid) {
	printf("[*] requesting process handle with terminate permission\n");
		Msg* msg = (Msg*)malloc(sizeof(Msg));
		memset(msg, 0, sizeof(Msg));
		msg->cmdType = enum_TerminateTargetProcess;
		msg->a1 = pid;

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (!hNtdll) {
			std::cerr << "Failed to get handle to ntdll.dll\n";
		 
		}

		FARPROC pRtlUserThreadStart = GetProcAddress(hNtdll, "RtlUserThreadStart");
		msg->a2 = (UCHAR*)pRtlUserThreadStart - (UCHAR*)hNtdll;
		HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hDevice == INVALID_HANDLE_VALUE) {
			printf("can't open custom kernel driver, error code: %d\n", GetLastError());
			return;
		}

		//
		// Printing Input & Output buffer pointers and size
		//

		//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
		//	sizeof(InputBuffer));
		//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
		//	sizeof(OutputBuffer));
		//
		// Performing METHOD_BUFFERED
		//

		StringCbCopy(InputBuffer, sizeof(InputBuffer),
			"This String is from User Application; using METHOD_BUFFERED");

		// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

		memset(OutputBuffer, 0, sizeof(OutputBuffer));
		DWORD bytesReturned = 0;
		bool bRc = DeviceIoControl(hDevice,
			(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
			msg,
			sizeof(Msg),
			&OutputBuffer,
			sizeof(OutputBuffer),
			&bytesReturned,
			NULL
		);

		if (!bRc)
		{
			printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
			free(msg);
			CloseHandle(hDevice);
			return;

		}
		HANDLE pHandle =(HANDLE ) *(DWORD*)(OutputBuffer);
		printf("[*] get target process handle: 0x%x, terminate now\n", pHandle);
		TerminateProcess(pHandle,0);
		//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
		free(msg);
		CloseHandle(hDevice);
	}
VOID SetFullPathInKernel(char* p) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_SetTargetProcessAbsFullPath;
	memcpy(&msg->a1, p, strlen(p));


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}

VOID  SetEntryPointOffsetOfTargetProcess(int off){
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_SetEPOff;
	msg->a1 = off;// processName, strlen(processName));


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}
VOID  SetTargetProcessFolderPath(char* processName) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_SetTargetProcessFolderPath;
	memcpy(&msg->a1, processName, strlen(processName));


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}
VOID  SetEntryRoutineHeadBytes(char* processName) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_SetEntryRoutineHeadBytes;
	memcpy(&msg->a1, processName, preSetEntryRoutineHeadBytesCount);


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}
VOID SetTargetProcessName(char* processName) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_SetTargetProcessName;
	memcpy(&msg->a1, processName, strlen(processName));


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}
VOID ChangeCallbackFunctionToXoreax_eax_ret(DWORD64 funcAddr) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_ChangeCallbackFunctionToXoreax_eax_ret;
	msg->a1 = funcAddr;


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	// printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}

char* GetFuncModulePath(DWORD64 funcAddr,char *_3bytesOut) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_GetFuncModulePath;
	msg->a1 = funcAddr;


	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return 0;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	////
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	//printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function ChangeCallbackFunctionToXoreax_eax_ret: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return 0;

	}
	// 后面有3字节是callback函数的原始指令
	char* modulePath = (char*)malloc(bytesReturned -3+ 1);
	memset(modulePath, 0, bytesReturned -3+ 1);
	memcpy(modulePath, OutputBuffer, bytesReturned-3);

	memcpy(_3bytesOut, OutputBuffer + bytesReturned - 3, 3);
	//printf("     q%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
	return modulePath;
}
VOID SetPPLOff(DWORD64 pplOff) {
	Msg* msg = (Msg*)malloc(sizeof(Msg));
	memset(msg, 0, sizeof(Msg));
	msg->cmdType = enum_SetPPLOff;
	msg->a1 = pplOff;
	msg->a2 = gEhtread_startAddrOff;

	HANDLE hDevice = CreateFile("\\\\.\\ObCallbackTest",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("can't open custom kernel driver, error code: %d\n", GetLastError());
		return;
	}

	//
	// Printing Input & Output buffer pointers and size
	//

	//printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
	//	sizeof(InputBuffer));
	//printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
	//	sizeof(OutputBuffer));
	//
	// Performing METHOD_BUFFERED
	//

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD_BUFFERED");

	//printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));
	DWORD bytesReturned = 0;
	bool bRc = DeviceIoControl(hDevice,
		(DWORD)IOCTL_SIOCTL_METHOD_BUFFERED,
		msg,
		sizeof(Msg),
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!bRc)
	{
		printf("Error in DeviceIoControl from function SetPPLOff: %d", GetLastError());
		free(msg);
		CloseHandle(hDevice);
		return;

	}
	//printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
	free(msg);
	CloseHandle(hDevice);
}


BOOLEAN
removeAndInstallKldbgdrvSetupDriverName(
	_Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
	_In_ ULONG BufferLength
)
{
	HANDLE fileHandle;
	DWORD driverLocLen = 0;

	//
	// Get the current directory.
	//

	driverLocLen = GetCurrentDirectory(BufferLength,
		DriverLocation
	);

	if (driverLocLen == 0) {

		printf("GetCurrentDirectory failed!  Error = %d \n", GetLastError());

		return FALSE;
	}
	//
	// Setup path name to driver file.
	//
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, BufferLength, "\\"DRIVER_NAME2".sys"))) {
		return FALSE;
	}

	//
	// Insure driver file is in the specified directory.
	//

	char fullPath[MAX_PATH] = { 0 };
	memset(DriverLocation, 0, sizeof(DriverLocation));
	GetModuleFileNameA(NULL, DriverLocation, MAX_PATH);

	// Strip off the executable name to get just the directory
	char* lastSlash = strrchr(DriverLocation, '\\');
	if (lastSlash) {
		*lastSlash = '\0'; // terminate the string at the last backslash
	}
#define FAILED(hr)      (((HRESULT)(hr)) < 0)
	if (FAILED(StringCbCat(DriverLocation, MAX_PATH, "\\"DRIVER_NAME2".sys"))) {
		return FALSE;
	}
	printf("[*] kldbgdrv driver location: %s\n", DriverLocation);
	if ((fileHandle = CreateFile(DriverLocation,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {


		printf("%s.sys is not loaded.\n", DRIVER_NAME);

		//
		// Indicate failure.
		//

		return FALSE;
	}

	//
	// Close open file handle.
	//

	if (fileHandle) {

		CloseHandle(fileHandle);
	}

	//
	// Indicate success.
	//

	return TRUE;


}   // SetupDriverName


BOOLEAN
removeAndInstallKldbgdrvManageDriver(
	_In_ LPCTSTR  DriverName,
	_In_ LPCTSTR  ServiceName,
	_In_ USHORT   Function
)
{

	SC_HANDLE   schSCManager;

	BOOLEAN rCode = TRUE;

	//
	// Insure (somewhat) that the driver and service names are valid.
	//

	if (!DriverName || !ServiceName) {

		printf("Invalid Driver or Service provided to ManageDriver() \n");

		return FALSE;
	}

	//
	// Connect to the Service Control Manager and open the Services database.
	//

	schSCManager = OpenSCManager(NULL,                   // local machine
		NULL,                   // local database
		SC_MANAGER_ALL_ACCESS   // access required
	);

	if (!schSCManager) {

		printf("Open SC Manager failed! Error = %d \n", GetLastError());

		return FALSE;
	}

	//
	// Do the requested function.
	//

	switch (Function) {

	case DRIVER_FUNC_INSTALL:

		//
		// Install the driver service.
		//
		//printf("driver name: %s\n", DriverName);
		//printf("service name: %s\n", ServiceName);
		if (InstallDriver(schSCManager,
			DriverName,
			ServiceName
		)) {

			//
			// Start the driver service (i.e. start the driver).
			//

			rCode = StartDriver(schSCManager,
				DriverName
			);

		}
		else {

			//
			// Indicate an error.
			//

			rCode = FALSE;
		}

		break;

	case DRIVER_FUNC_REMOVE:

		//
		// Stop the driver.
		//

		StopDriver(schSCManager,
			DriverName
		);

		//
		// Remove the driver service.
		//

		RemoveDriver(schSCManager,
			DriverName
		);

		//
		// Ignore all errors.
		//

		rCode = TRUE;

		break;

	default:

		printf("Unknown ManageDriver() function. \n");

		rCode = FALSE;

		break;
	}

	//
	// Close handle to service control manager.
	//

	if (schSCManager) {

		CloseServiceHandle(schSCManager);
	}

	return rCode;

}   // ManageDriver

BOOLEAN
removeAndInstallKldbgdrvInstallDriver(
	_In_ SC_HANDLE  SchSCManager,
	_In_ LPCTSTR    DriverName,
	_In_ LPCTSTR    ServiceExe
)
/*++

Routine Description:

Arguments:

Return Value:

--*/
{
	SC_HANDLE   schService;
	DWORD       err;

	//
	// NOTE: This creates an entry for a standalone driver. If this
	//       is modified for use with a driver that requires a Tag,
	//       Group, and/or Dependencies, it may be necessary to
	//       query the registry for existing driver information
	//       (in order to determine a unique Tag, etc.).
	//

	//
	// Create a new a service object.
	//

	schService = CreateService(SchSCManager,           // handle of service control manager database
		DriverName,             // address of name of service to start
		DriverName,             // address of display name
		SERVICE_ALL_ACCESS,     // type of access to service
		SERVICE_KERNEL_DRIVER,  // type of service
		SERVICE_DEMAND_START,   // when to start service
		SERVICE_ERROR_NORMAL,   // severity if service fails to start
		ServiceExe,             // address of name of binary file
		NULL,                   // service does not belong to a group
		NULL,                   // no tag requested
		NULL,                   // no dependency names
		NULL,                   // use LocalSystem account
		NULL                    // no password for service account
	);

	if (schService == NULL) {

		err = GetLastError();

		if (err == ERROR_SERVICE_EXISTS) {

			//
			// Ignore this error.
			//

			return TRUE;

		}
		else {

			printf("CreateService failed!  Error = %d \n", err);

			//
			// Indicate an error.
			//

			return  FALSE;
		}
	}

	//
	// Close the service object.
	//

	if (schService) {

		CloseServiceHandle(schService);
	}

	//
	// Indicate success.
	//

	return TRUE;

}   // InstallDriver
VOID removeAndInstallKldbgdrv() {
	TCHAR driverLsocation[MAX_PATH];
	removeAndInstallKldbgdrvSetupDriverName(driverLsocation, sizeof(driverLsocation));
	removeAndInstallKldbgdrvManageDriver(DRIVER_NAME2,
		driverLsocation,
		DRIVER_FUNC_REMOVE
	);

	removeAndInstallKldbgdrvManageDriver(DRIVER_NAME2,
		driverLsocation,
		DRIVER_FUNC_INSTALL
	);
}
VOID removeKldbgdrv() {
	TCHAR driverLsocation[MAX_PATH];
	removeAndInstallKldbgdrvSetupDriverName(driverLsocation, sizeof(driverLsocation));
	removeAndInstallKldbgdrvManageDriver(DRIVER_NAME2,
		driverLsocation,
		DRIVER_FUNC_REMOVE
	);
}