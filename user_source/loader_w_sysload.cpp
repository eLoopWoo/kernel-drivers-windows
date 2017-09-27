#include <windows.h>
#include <stdio.h>
#include <iostream>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef long NTSTATUS;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef NTSTATUS (__stdcall *ZWSETSYSTEMINFORMATION)(
            DWORD SystemInformationClass,
			PVOID SystemInformation,
			ULONG SystemInformationLength
);

typedef VOID (__stdcall *RTLINITUNICODESTRING)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
);

ZWSETSYSTEMINFORMATION ZwSetSystemInformation;
RTLINITUNICODESTRING RtlInitUnicodeString;

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE
{
 UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE;

#define SystemLoadAndCallImage 38

BOOL load_sysfile() {
	SYSTEM_LOAD_AND_CALL_IMAGE GregsImage;
	WCHAR daPath[] = L"\\??\\C:\\DCOM.SYS";

	if(!(RtlInitUnicodeString = (RTLINITUNICODESTRING)
			GetProcAddress( GetModuleHandle("ntdll.dll")
			  ,"RtlInitUnicodeString"
			)))
	{
		return FALSE;
	}

	if(!(ZwSetSystemInformation = (ZWSETSYSTEMINFORMATION)
				GetProcAddress(
					GetModuleHandle("ntdll.dll")
					,"ZwSetSystemInformation" )))
	{
		return FALSE;
	}

	RtlInitUnicodeString(
		&(GregsImage.ModuleName)
		,daPath
	);

	if(!NT_SUCCESS(
		  ZwSetSystemInformation(
			SystemLoadAndCallImage
			,&GregsImage
			,sizeof(SYSTEM_LOAD_AND_CALL_IMAGE))))
	{
		return FALSE;
	}

	return TRUE;
}


int main(){
    load_sysfile();
    return 0;
}
