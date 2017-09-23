#include "header_help.h"

#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]

#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)

#define HOOK_SYSCALL(_Function, _Hook, _Orig ) _Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig ) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)


struct _SYSTEM_THREADS
{
        LARGE_INTEGER           KernelTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           CreateTime;
        ULONG                           WaitTime;
        PVOID                           StartAddress;
        CLIENT_ID                       ClientIs;
        KPRIORITY                       Priority;
        KPRIORITY                       BasePriority;
        ULONG                           ContextSwitchCount;
        ULONG                           ThreadState;
        KWAIT_REASON            WaitReason;
};

struct _SYSTEM_PROCESSES
{
        ULONG                           NextEntryDelta;
        ULONG                           ThreadCount;
        ULONG                           Reserved[6];
        LARGE_INTEGER           CreateTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           KernelTime;
        UNICODE_STRING          ProcessName;
        KPRIORITY                       BasePriority;
        ULONG                           ProcessId;
        ULONG                           InheritedFromProcessId;
        ULONG                           HandleCount;
        ULONG                           Reserved2[2];
        VM_COUNTERS                     VmCounters;
        IO_COUNTERS                     IoCounters; //windows 2000 only
        struct _SYSTEM_THREADS          Threads[1];
};




NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength);


typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(
            ULONG SystemInformationCLass,
			PVOID SystemInformation,
			ULONG SystemInformationLength,
			PULONG ReturnLength
);

ZWQUERYSYSTEMINFORMATION OldZwQuerySystemInformation;

NTSTATUS NewZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
            IN PVOID SystemInformation,
            IN ULONG SystemInformationLength,
            OUT PULONG ReturnLength){
	NTSTATUS ntStatus;
	ntStatus = ((ZWQUERYSYSTEMINFORMATION)(OldZwQuerySystemInformation)) (
				SystemInformationClass,
				SystemInformation,
				SystemInformationLength,
				ReturnLength );
	DbgPrint("ssdt is hooked :)");
	return ntStatus;
	
}
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	DbgPrint("OnUnload called\n");
}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath){
	DbgPrint("DriverEntry called\n");
	theDriverObject->DriverUnload  = OnUnload; 

	OldZwQuerySystemInformation =(ZWQUERYSYSTEMINFORMATION)(SYSTEMSERVICE(ZwQuerySystemInformation));

	g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices*4);
	if(!g_pmdlSystemCall)
		return STATUS_UNSUCCESSFUL;
	MmBuildMdlForNonPagedPool(g_pmdlSystemCall);

	g_pmdlSystemCall->MdlFlags = g_pmdlSystemCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;
	MappedSystemCallTable = MmMapLockedPages(g_pmdlSystemCall, KernelMode);

	HOOK_SYSCALL( ZwQuerySystemInformation, NewZwQuerySystemInformation, OldZwQuerySystemInformation );
							  
	return STATUS_SUCCESS;
}
