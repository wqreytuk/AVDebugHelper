/*++

Module Name:

    shared.h

Abstract:

    This contains declarations shared by the Ob/Ps callback test driver and
    the user mode test app.


// Notice:
//
//    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
//    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
//    (http://www.microsoft.com/opensource/licenses.mspx)

--*/

#pragma once

#pragma warning(disable:4214) // bit field types other than int
#pragma warning(disable:4201) // nameless struct/union

//
// TD_ASSERT
//
// This macro is identical to NT_ASSERT but works in fre builds as well.
//
// It is used for error checking in the driver in cases where
// we can't easily report the error to the user mode app, or the
// error is so severe that we should break in immediately to
// investigate.
//
// It's better than DbgBreakPoint because it provides additional info
// that can be dumped with .exr -1, and individual asserts can be disabled
// from kd using 'ahi' command.
//

#define TD_ASSERT(_exp) \
    ((!(_exp)) ? \
        (__annotation(L"Debug", L"AssertFail", L#_exp), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

//
// Driver and device names
// It is important to change the names of the binaries
// in the sample code to be unique for your own use.
//

#define TD_DRIVER_NAME             L"ObCallbackTest"
#define TD_DRIVER_NAME_WITH_EXT    L"ObCallbackTest.sys"

#define TD_NT_DEVICE_NAME          L"\\Device\\ObCallbackTest"
#define TD_DOS_DEVICES_LINK_NAME   L"\\DosDevices\\ObCallbackTest"
#define TD_WIN32_DEVICE_NAME       L"\\\\.\\ObCallbackTest"


#define NAME_SIZE   200

#define TD_INVALID_CALLBACK_ID ((ULONG)-1)

//
// IOCTLs exposed by the driver.
//

// #define TD_IOCTL_REGISTER_CALLBACK   CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 0), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
// #define TD_IOCTL_UNREGISTER_CALLBACK CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 1), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define TD_IOCTL_PROTECT_NAME_CALLBACK        CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 2), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define TD_IOCTL_UNPROTECT_CALLBACK           CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 3), METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


#define TDProtectName_Protect  0            // name of programs to proect and filter out the desiredAccess on Process Open
#define TDProtectName_Reject   1            // name of programs to reject during ProcessCreate

//
// Structures used by TD_IOCTL_PROTECTNAME
//

typedef struct _TD_PROTECTNAME_INPUT {
    ULONG Operation;
    WCHAR Name[NAME_SIZE+1];      // what is the filename to protect - extra wchar for forced NULL
}
TD_PROTECTNAME_INPUT, *PTD_PROTECTNAME_INPUT;

//
// Structures used by TD_IOCTL_UNPROTECT_CALLBACK
//

typedef struct _TD_UNPROTECT_CALLBACK_INPUT {
    ULONG UnusedParameter;
}
TD_UNPROTECT_CALLBACK_INPUT, *PTD_UNPROTECT_CALLBACK_INPUT;






//
// Device type           -- in the "User Defined" range."
//
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

#define DRIVER_NAME       "ObCallbackTest"


typedef struct _Msg {
	DWORD cmdType;
	DWORD64 a1;
	DWORD64 a2;
	DWORD64 a3;
	DWORD64 a4;
	DWORD64 a5;
	DWORD64 a6;
	DWORD64 a7;
	DWORD64 a8;
	DWORD64 a9;
	DWORD64 a10;
	DWORD64 a11;
	DWORD64 a12;
	DWORD64 a13;
	DWORD64 a14;
	DWORD64 a15;
	DWORD64 a16;
}Msg;
#define  enum_ChangeCallbackFunctionToXoreax_eax_ret 0
#define  enum_SetTargetProcessName 1
#define  enum_StopThreadCreateSleep 2
#define  enum_SetPPLOff 3
#define  enum_GetFuncModulePath 4
#define  enum_DisablePPL 5
#define  enum_CheckPPL 6
#define  enum_DebugFromBeginning 7
#define preSetEntryRoutineHeadBytesCount 0x10
#define  enum_SetEntryRoutineHeadBytes 8
#define  enum_TerminateTargetProcess 9
#define  enum_AskKernelIfTargetProcessIsCrashed 10
#define enum_RestoreObjectCallback 11
#define enum_SetTargetProcessFolderPath 12
#define enum_SetTargetProcessAbsFullPath 13
#define enum_SetEPOff 14
