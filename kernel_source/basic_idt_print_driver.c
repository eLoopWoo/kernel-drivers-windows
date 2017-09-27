#include "header_help.h"
#include <stdio.h>

#define MAKELONG(a, b) ((unsigned long) (((unsigned short) (a)) | ((unsigned long) ((unsigned short) (b))) << 16))
#define MAX_IDT_ENTRIES 0xFF

typedef struct
{
	unsigned short IDTLimit;
	unsigned short LowIDTbase;
	unsigned short HiIDTbase;
	} IDTINFO;

typedef struct
{
	unsigned short LowOffset;
	unsigned short selector;
	unsigned char unused_lo;
	unsigned char segment_type:4;
	unsigned char system_segment_flag:1;
	unsigned char DPL:2; // descriptor privilege level
	unsigned char P:1;
	unsigned short HiOffset;
} IDTENTRY;



NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	IDTINFO idt_info;
	IDTENTRY* idt_entries;
	unsigned long count;
	__asm sidt idt_info

	idt_entries = (IDTENTRY*)
	MAKELONG(idt_info.LowIDTbase, idt_info.HiIDTbase);
	for(count = 0;count <= MAX_IDT_ENTRIES;count++){
		char _t[255];
		IDTENTRY *i = &idt_entries[count];
		unsigned long addr = 0;
		addr = MAKELONG(i->LowOffset,  i->HiOffset);
		_snprintf(_t, 253, "Interrupt %d: ISR 0x%08X", count, addr);
		DbgPrint(_t);
	}
	return STATUS_SUCCESS;
}