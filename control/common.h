
// Notice:
//
//    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
//    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
//    (http://www.microsoft.com/opensource/licenses.mspx)

#pragma once

#pragma warning (disable: 4201) // nonstandard extension used : nameless struct/union

#include "..\driver\shared.h"

//
// Logging support macros.
//
// LOG_INFO
// LOG_INFO_FAILURE
// LOG_PASSED
// LOG_ERROR
//


#ifdef DEBUG
#define LOG_INFO(fmt, ...)         \
    _tprintf(_T("%hs: ") fmt, __FUNCTION__, __VA_ARGS__);_tprintf(_T("\n"));
#define LOG_INFO_FAILURE(fmt, ...) \
    _tprintf(_T("ReportFailure %hs: ") fmt, __FUNCTION__, __VA_ARGS__);_tprintf(_T("\n"));

#define LOG_PASSED(fmt, ...)       \
    _tprintf(_T("\n!!!PASSED: %hs (%hs:%u): ") fmt, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__);_tprintf(_T("\n"));
#define LOG_ERROR(fmt, ...)        \
    _tprintf(_T("\n!!!FAILED: %hs (%hs:%u): ") fmt, __FUNCTION__, __FILE__, __LINE__, __VA_ARGS__); _tprintf(_T("\n"));

#else

#define LOG_INFO(FormatString, ...)    
#define LOG_INFO_FAILURE(FormatString, ...) 

#define LOG_PASSED(FormatString, ...)      
#define LOG_ERROR(FormatString, ...)   

#endif


extern HANDLE TcDeviceHandle;

BOOL TcInitialize();
BOOL TcUnInitialize();
BOOL TcCleanupSCM();

BOOL TcInstallDriver();

BOOL TcUninstallDriver();

BOOL TcRemoveProtection ();

BOOL TcProcessName (
    _In_ int argc,
    _In_reads_(argc) LPCWSTR argv[],
    _In_ ULONG ulOperation
);

BOOL TcUnprotectCallback ();

BOOL TcProcessNameCallback (
    _In_reads_(NAME_SIZE+1) PCWSTR  pnametoprotect,
    _In_ ULONG ulOperation
);

//
// Utility functions
//

BOOL TcInitializeGlobals();
BOOL TcLoadDriver();
BOOL TcUnloadDriver();

BOOL TcCreateService();
BOOL TcDeleteService();
BOOL TcStartService();
BOOL TcStopService();

BOOL TcOpenDevice();
BOOL TcCloseDevice();

#define SIOCTL_TYPE 40000
//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define IOCTL_SIOCTL_METHOD_IN_DIRECT \
    CTL_CODE( SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_METHOD_OUT_DIRECT \
    CTL_CODE( SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT , FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_METHOD_BUFFERED \
    CTL_CODE( SIOCTL_TYPE, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define IOCTL_SIOCTL_METHOD_NEITHER \
    CTL_CODE( SIOCTL_TYPE, 0x903, METHOD_NEITHER , FILE_ANY_ACCESS  )


#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02

#define DRIVER_NAME       "SIoctl"


typedef struct _Msg {
	DWORD cmdType;
	DWORD64 a1;
	DWORD64 a2;
	DWORD64 a3;
	DWORD64 a4;
	DWORD64 a5;
	DWORD64 a6;
}Msg;
#define  enum_ChangeCallbackFunctionToXoreax_eax_ret 0