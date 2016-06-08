/*
 * Copyright 2010 coderebasoft
 *
 * This file is part of PEMaster.
 *
 * PEMaster is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PEMaster is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PEMaster.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "ddk.h"

#define INVALID_EXPORT_ORDER 0xffff 
#pragma data_seg( ".gdata" )

typedef unsigned long DWORD, *PDWORD; 
typedef unsigned char BYTE, *PBYTE; 
typedef unsigned short WORD, *PWORD; 
typedef int BOOL; 
typedef void *PVOID; 

#define OLD_IMAGE_SIZE 0
#define PACKET_DATA_RVA 1
#define UNPACK_SPACE_RVA 2
#define IMPORT_RVA 3
#define RELOC_RVA 4
#define OLD_IMAGE_BASE 5
#define OEP 6
#define ALL_SHELL_INFO_SIZE 7

#define APLIB_ERROR (-1)
#define MAX_PACK_SECTION_NUM 10

#define VOID void

typedef struct _PACKET_INFO 
{
	DWORD vsize;
	DWORD vaddr;
	DWORD packed_size;
	DWORD unpack_size;
}PACKET_INFO,*PPACKET_INFO ;

typedef struct {
	const unsigned char *source;
	unsigned int srclen;
	unsigned char *destination;
	unsigned int dstlen;
	unsigned int tag;
	unsigned int bitcount;
} APDEPACKSAFEDATA;

#ifndef _RING3_TEST
typedef PVOID ( __stdcall *ALLOC_MEM )( IN POOL_TYPE PoolType, IN SIZE_T NumberOfBytes );
typedef VOID ( __stdcall *FREE_MEM )( IN PVOID P );
typedef ULONG ( _cdecl *DBG_PRINT )( IN PCHAR Format, ... );

WCHAR depend_module[] = L"ntoskrnl.exe";
WCHAR depend_module_other[] = L"ntkrnl";
CHAR mem_alloc_func_name[] = "ExAllocatePool";
CHAR mem_free_func_name[] = "ExFreePool";

//WCHAR hal_module[] = L""; 
//CHAR hold_spin_lock_name[] = ""

#ifdef _PRINT_DEBUG
CHAR dbg_print_func_name[] = "DbgPrint";
#endif 

#else
typedef PVOID ( __stdcall *ALLOC_MEM )( IN SIZE_T NumberOfBytes );
typedef VOID ( __stdcall *FREE_MEM )( IN PVOID P );
typedef ULONG ( _cdecl *DBG_PRINT )( IN PCHAR Format, ... );

WCHAR depend_module[] = L"msvcrt.dll";
CHAR mem_alloc_func_name[] = "malloc";
CHAR mem_free_func_name[] = "free";

CHAR dbg_print_func_name[] = "printf";

#endif

typedef VOID ( __stdcall *driver_unload )( struct _DRIVER_OBJECT *DriverObject );

typedef NTSTATUS ( __stdcall *ZW_CLOSE )( IN HANDLE Handle ); 

typedef NTSTATUS ( __stdcall *ZW_WRITE_FILE )( IN HANDLE FileHandle, 
									IN HANDLE Event OPTIONAL, 
									IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, 
									IN PVOID ApcContext OPTIONAL, 
									OUT PIO_STATUS_BLOCK IoStatusBlock, 
									IN PVOID Buffer, 
									IN ULONG Length, 
									IN PLARGE_INTEGER ByteOffset OPTIONAL, 
									IN PULONG Key OPTIONAL ); 

typedef NTSTATUS ( __stdcall *ZW_CREATE_FILE )( OUT PHANDLE FileHandle, 
									 IN ACCESS_MASK DesiredAccess,
									 IN POBJECT_ATTRIBUTES ObjectAttributes, 
									 OUT PIO_STATUS_BLOCK IoStatusBlock, 
									 IN PLARGE_INTEGER AllocationSize OPTIONAL, 
									 IN ULONG FileAttributes, 
									 IN ULONG ShareAccess, 
									 IN ULONG CreateDisposition, 
									 IN ULONG CreateOptions, 
									 IN PVOID EaBuffer OPTIONAL, 
									 IN ULONG EaLength );

typedef VOID ( __stdcall *RTL_FREE_UNICODE_STRING )( PUNICODE_STRING UnicodeString );

typedef NTSTATUS ( __stdcall *RTL_APPEND_UNICODE_STRING_TO_STRING )( PUNICODE_STRING Destination, PCUNICODE_STRING Source );

typedef NTSTATUS ( __stdcall *RTL_ANSI_STRING_TO_UNICODE_STRING )( PUNICODE_STRING DestinationString, 
													 PCANSI_STRING SourceString, 
													 BOOLEAN AllocateDestinationString );

typedef VOID ( __stdcall *RTL_INIT_ANSI_STRING )( PANSI_STRING DestinationString, PCSZ SourceString );

typedef VOID ( __stdcall *RTL_COPY_UNICODE_STRING )( PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString );

CHAR mod_dump_file_name[] = "\\??\\D:\\unpacked_mod"; 

CHAR close_file_func_name[] = "ZwClose"; 
CHAR write_file_func_name[] = "ZwWriteFile";
CHAR create_file_func_name[] = "ZwCreateFile";
CHAR free_uni_str_func_name[] = "RtlFreeUnicodeString";
CHAR append_uni_str_func_name[] = "RtlAppendUnicodeStringToString";
CHAR ansi_to_uni_str_func_name[] = "RtlAnsiStringToUnicodeString"; 
CHAR init_ansi_str_func_name[] = "RtlInitAnsiString"; 
CHAR copy_uni_str_func_name[] = "RtlCopyUnicodeString"; 

#ifdef _PRINT_DEBUG
CHAR data_fmt[] = "%X\n";
CHAR print_banner[] = "do decompressing\n"; 
CHAR print_sys_img_info[] = "sys image base is 0x%0.8x, origianl image size is %d, unpack to buffer 0x%0.8x \n"; 
CHAR print_sys_pack_info[] = "unpack section vaddr 0x%0.8x, vsize %d packed size %d, unpack size %d \n"; 
CHAR print_old_img_size[] = "OLD_IMAGE_SIZE: %d \n"; 
CHAR print_get_mod_base_err[] = "get module base error %ws \n"; 
CHAR print_get_func_addr_by_name[] = "get function addr by name %s func addr 0x%0.8x write to 0x%0.8x \n"; 
CHAR print_get_func_addr_by_order[] = "get function addr by order %d func addr 0x%0.8x write to 0x%0.8x \n"; 
CHAR print_image_base_diff[] = "orginal image base is 0x%0.8x, unpacked image base is 0x%0.8x difference 0x%0.8x \n"; 
CHAR print_reloc_diff[] = "write addr is 0x%0.8x, orginal reloc is 0x%0.8x, corrected reloc is 0x%0.8x \n"; 
CHAR print_call_unpack_mod_unload[] = "call unpacked mod unload routine 0x%0.8x\n"; 
CHAR print_unpack_img_no_record[] = "fatal error! unload but the unpack image base is not recorded \n"; 
CHAR print_all_released[] = "all is released successfully \n"; 
CHAR print_free_unpack_img[] = "free unpack image 0x%0.8x"; 
CHAR print_get_func_by_name_err[] = "fatal error! get import function ( %s ) addr err.\n"; 
CHAR print_get_func_by_order_err[] = "fatal error! get import function ( %d ) addr err.\n";
CHAR print_reloc_is_zero[] = "reloc offset is 0, the reloc count is %d \n"; 
CHAR print_reloc_offset[] = "reloc type %d reloc base offset 0x%0.8x, offset 0x%0.8x, unpack image base 0x%0.8x\n"; 

CHAR print_enter_write_func[] = "enter WriteBufferToFile"; 
CHAR print_alloc_name_buff_err[] = "alloc the unicode string buffer error"; 
CHAR print_conv_name_err[] = "convert the file name to the unicoe error"; 
CHAR append_file_path_err[] = "append file path error"; 
CHAR print_open_file_err[] = "open the file error"; 
CHAR print_write_file_err[] = "write file error"; 
CHAR print_exit_write_buff[] = "exit WriteBufferToFile successly"; 
#endif

driver_unload pack_mod_unload = NULL; 
PVOID unpacked_image = NULL; 

PACKET_INFO pack_infos[ MAX_PACK_SECTION_NUM ] = { 0 };//保存每个压缩区段的信息
DWORD shell_infos[ ALL_SHELL_INFO_SIZE ] = { 0 };

CHAR end[ 10 ]="shell_end";

#pragma data_seg()


#pragma code_seg(".gcode")
 INT32 _stdcall aP_getbit_safe( APDEPACKSAFEDATA *ud, unsigned int *result )
{
	unsigned int bit;

	/* check if tag is empty */
	if( !ud->bitcount-- )
	{
		if( !ud->srclen-- ) return 0;

		/* load next tag */
		ud->tag = *ud->source++;
		ud->bitcount = 7;
	}

	/* shift bit out of tag */
	bit = ( ud->tag >> 7 ) & 0x01;
	ud->tag <<= 1;

	*result = bit;

	return 1;
}

//__declspec( naked ) VOID __stdcall anti_debug1()
//{
//	__asm
//	{
//		xor eax, eax; 
//		push dword ptr fs:[eax]; 
//		mov dword ptr fs:[eax], esp; 
//		push ebx; 
//		xor ebx, ebx; 
//		add dword ptr [ ebx ], 0; 
//		pop ebx;
//		pop fs:[ eax ]; 
//		ret; 
//	}
//}
//
//INT32 __stdcall anti_debug2()
//{
//	GetExceptionInformation()->Eip += 4; 
//	return 1; 
//}
//
//__declspec( naked ) VOID __stdcall anti_debug3()
//{
//	__asm
//	{
//		call dword ptr [ anti_debug1 ]; 
//		call dword ptr [ anti_debug2 ]; 
//		ret; 
//	}
//}

INT32 _stdcall aP_getgamma_safe( APDEPACKSAFEDATA *ud, unsigned int *result )
{
	unsigned int bit;
	unsigned int v = 1;

	/* input gamma2-encoded bits */
	do {

		if( !aP_getbit_safe( ud, &bit ) ) return 0;

		v = ( v << 1 ) + bit;

		if ( !aP_getbit_safe( ud, &bit ) ) return 0;

	} while ( bit );

	*result = v;

	return 1;
}

INT32 _stdcall aP_depack_safe(const void *source,
							unsigned int srclen,
							void *destination,
							unsigned int dstlen)
{
	APDEPACKSAFEDATA ud;
	unsigned int offs, len, R0 = 0, LWM, bit;
	int done;
	int i;

	if (!source || !destination) return APLIB_ERROR;

	ud.source = (const unsigned char *) source;
	ud.srclen = srclen;
	ud.destination = (unsigned char *) destination;
	ud.dstlen = dstlen;
	ud.bitcount = 0;

	LWM = 0;
	done = 0;

	/* first byte verbatim */
	if (!ud.srclen-- || !ud.dstlen--) return APLIB_ERROR;
	*ud.destination++ = *ud.source++;

	/* main decompression loop */
	while (!done)
	{
		if (!aP_getbit_safe(&ud, &bit)) return APLIB_ERROR;

		if (bit)
		{
			if (!aP_getbit_safe(&ud, &bit)) return APLIB_ERROR;

			if (bit)
			{
				if (!aP_getbit_safe(&ud, &bit)) return APLIB_ERROR;

				if (bit)
				{
					offs = 0;

					for (i = 4; i; i--)
					{
						if (!aP_getbit_safe(&ud, &bit)) return APLIB_ERROR;
						offs = (offs << 1) + bit;
					}

					if (offs)
					{
						if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

						if (!ud.dstlen--) return APLIB_ERROR;

						*ud.destination = *(ud.destination - offs);
						ud.destination++;

					} else {

						if (!ud.dstlen--) return APLIB_ERROR;

						*ud.destination++ = 0x00;
					}

					LWM = 0;

				} else {

					if (!ud.srclen--) return APLIB_ERROR;

					offs = *ud.source++;

					len = 2 + (offs & 0x0001);

					offs >>= 1;

					if (offs)
					{
						if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

						if (len > ud.dstlen) return APLIB_ERROR;

						ud.dstlen -= len;

						for (; len; len--)
						{
							*ud.destination = *(ud.destination - offs);
							ud.destination++;
						}
					} else done = 1;

					R0 = offs;
					LWM = 1;
				}

			} else {

				if (!aP_getgamma_safe(&ud, &offs)) return APLIB_ERROR;

				if ((LWM == 0) && (offs == 2))
				{
					offs = R0;

					if (!aP_getgamma_safe(&ud, &len)) return APLIB_ERROR;

					if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

					if (len > ud.dstlen) return APLIB_ERROR;

					ud.dstlen -= len;

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

				} else {

					if (LWM == 0) offs -= 3; else offs -= 2;

					if (!ud.srclen--) return APLIB_ERROR;

					offs <<= 8;
					offs += *ud.source++;

					if (!aP_getgamma_safe(&ud, &len)) return APLIB_ERROR;

					if (offs >= 32000) len++;
					if (offs >= 1280) len++;
					if (offs < 128) len += 2;

					if (offs > (dstlen - ud.dstlen)) return APLIB_ERROR;

					if (len > ud.dstlen) return APLIB_ERROR;

					ud.dstlen -= len;

					for (; len; len--)
					{
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

					R0 = offs;
				}

				LWM = 1;
			}

		} else {

			if (!ud.srclen-- || !ud.dstlen--) return APLIB_ERROR;
			*ud.destination++ = *ud.source++;
			LWM = 0;
		}
	}

	return ud.destination - (unsigned char *) destination;
}

INLINE INT32 _stdcall inline_strcmp( CHAR *src, CHAR *dst )
{
	while ( *src != 0 && *dst != 0 )
	{
		int r = *src - *dst;
		if ( r != 0 )
			return r;
		
		src++;
		dst++;
	}
	return ( *src != 0 || *dst != 0 ) ? *src - *dst : 0;
}

INLINE PVOID _stdcall inline_memset(void* dst, int c, size_t len)
{
	BYTE* p = (BYTE*)dst;
	ASSERT( NULL != dst ); 
	while ( len-- != 0 )
		*p++ = ( BYTE )c;
	
	return dst;
}

INLINE PVOID _stdcall inline_memcpy( PVOID dst, PVOID src, size_t len )
{
	BYTE* p = ( BYTE* )dst;
	BYTE* q = ( BYTE* )src;

	ASSERT( dst != NULL ); 
	ASSERT( src != NULL ); 

	while ( len-- != 0 )
		*p++ = *q++;
	
	return dst;
}


__declspec( naked ) PVOID get_kern_base()
{
	_asm
	{
		push 30h;
		pop fs;
		//mov eax, 0x30; 
		//mov fs, ax; 
		mov eax, dword ptr fs:[ 34h ];
		mov eax, [ eax + 10h ];
		ret;
	}
}

//004053FA    64:67:A1 0000   mov     eax, dword ptr fs:[0]
//004053FF    8338 FF         cmp     dword ptr [eax], -1
//00405402    74 04           je      short 00405408
//00405404    8B00            mov     eax, dword ptr [eax]
//00405406  ^ EB F7           jmp     short 004053FF
//00405408    8B48 04         mov     ecx, dword ptr [eax+4]
//0040540B    33D2            xor     edx, edx
//0040540D    49              dec     ecx
//0040540E    66:8B51 3C      mov     dx, word ptr [ecx+3C]
//00405412    66:F7C2 00F8    test    dx, 0F800
//00405417  ^ 75 F2           jnz     short 0040540B
//00405419    3B4C11 34       cmp     ecx, dword ptr [ecx+edx+34]
//0040541D  ^ 75 EC           jnz     short 0040540B
//0040541F    898D B80B0000   mov     dword ptr [ebp+BB8], ecx
//00405425    898D BC0B0000   mov     dword ptr [ebp+BBC], ecx
//0040542B    C3              retn
//0040542C    C785 A90A0000 0>mov     dword ptr [ebp+AA9], 0
//00405436    33DB            xor     ebx, ebx
//00405438    46              inc     esi
//

__declspec( naked ) INLINE PVOID _stdcall get_kernel32_mod_base()
{
	_asm
	{
		push ecx; 
		push edx; 
		mov eax, dword ptr fs:[ 0 ]; 

compare_seh_end:
		cmp dword ptr [ eax ], -1; 
		jz locate_to_kern_mod_base; 
		mov eax, dword ptr [ eax ]; 
		jmp compare_seh_end; 

locate_to_kern_mod_base:
		mov ecx, dword ptr [ eax + 4 ]; 
		xor edx, edx; 
		and ecx, 0xfffff000; 

check_pe_sign_again:
		mov dx, word ptr [ ecx + 0x3C ]; 
		test dx, 0xf800; 
		jz check_other_pe_sign; 
		sub ecx, 0x1000; 
		jmp check_pe_sign_again;

check_other_pe_sign:
		cmp ecx, dword ptr [ ecx + edx + 0x34 ]; 
		jz _return; 
		sub ecx, 0x1000; 
		jmp check_pe_sign_again; 
_return:
		mov eax, ecx; 
		pop edx; 
		pop ecx; 

		ret; 
	}
}

INLINE PVOID _stdcall relocate_addr_in_other_image( PVOID addr )
{
	PVOID correct_addr = NULL;
	__asm
	{

_start:
		call lbl_next

lbl_next:
		pop eax; 
		sub eax, 5; 
		sub eax, offset _start; 
		add eax, addr; 
		mov dword ptr [ correct_addr ], eax; 
	}

	//DBGPRINT( ( "got global variable 0x%0.8x \n", correct_addr ) ); 
	return correct_addr;
}

INLINE CHAR toupper( WCHAR ch )
{
	if( ch >= L'a' && ch <= L'z' )
	{
		return ch + L'A' - L'a'; 
	}
	return ch; 
}

INLINE INT32 _stdcall inline_wstrcmp(WCHAR * src, WCHAR *dst,int len)
{
	INT32 i;

	for( i = 0; i < len / 2; i++ )
	{
		if( toupper( src[ i ] ) != toupper( dst[ i ] ) )
		{
			return src[ i ] - dst[ i ];
		}

	}
	return 0;

}

//#pragma pack( push )
//#pragma pack( 1 )
//#define IMAGE_DOS_SIGNATURE                 0x4D5A      // MZ
//#define IMAGE_OS2_SIGNATURE                 0x4E45      // NE
//#define IMAGE_OS2_SIGNATURE_LE              0x4C45      // LE
//#define IMAGE_NT_SIGNATURE                  0x50450000  // PE00
//
//#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
//#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
//#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
//#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
//#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
//#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
//#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
////      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
//#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
//#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
//#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
//#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
//#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
//#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
//#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
//#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
//
//typedef struct _IMAGE_BASE_RELOCATION {
//    DWORD   VirtualAddress;
//    DWORD   SizeOfBlock;
//	WORD    TypeOffset[1];
//} IMAGE_BASE_RELOCATION;
//typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
//
//typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
//    WORD   e_magic;                     // Magic number
//    WORD   e_cblp;                      // Bytes on last page of file
//    WORD   e_cp;                        // Pages in file
//    WORD   e_crlc;                      // Relocations
//    WORD   e_cparhdr;                   // Size of header in paragraphs
//    WORD   e_minalloc;                  // Minimum extra paragraphs needed
//    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
//    WORD   e_ss;                        // Initial (relative) SS value
//    WORD   e_sp;                        // Initial SP value
//    WORD   e_csum;                      // Checksum
//    WORD   e_ip;                        // Initial IP value
//    WORD   e_cs;                        // Initial (relative) CS value
//    WORD   e_lfarlc;                    // File address of relocation table
//    WORD   e_ovno;                      // Overlay number
//    WORD   e_res[4];                    // Reserved words
//    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
//    WORD   e_oeminfo;                   // OEM information; e_oemid specific
//    WORD   e_res2[10];                  // Reserved words
//    LONG   e_lfanew;                    // File address of new exe 
//} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

//
// Loader Data Table. Used to track DLLs loaded into an
// image.
//

//#pragma warning( push )
//#pragma warning( disable:4201 )
//typedef struct _LDR_DATA_TABLE_ENTRY {
//    LIST_ENTRY InLoadOrderLinks;
//    LIST_ENTRY InMemoryOrderLinks;
//    LIST_ENTRY InInitializationOrderLinks;
//    PVOID DllBase;
//    PVOID EntryPoint;
//    ULONG SizeOfImage;
//    UNICODE_STRING FullDllName;
//    UNICODE_STRING BaseDllName;
//    ULONG Flags;
//    USHORT LoadCount;
//    USHORT TlsIndex;
//    union {
//        LIST_ENTRY HashLinks;
//        struct {
//            PVOID SectionPointer;
//            ULONG CheckSum;
//        };
//    };
//    union {
//        struct {
//            ULONG TimeDateStamp;
//        };
//        struct {
//            PVOID LoadedImports;
//        };
//    };
//    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
//
//    PVOID PatchInformation;
//
//} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//
//typedef struct _IMAGE_DATA_DIRECTORY {
//    DWORD   VirtualAddress;
//    DWORD   Size;
//} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
//
//typedef struct _IMAGE_EXPORT_DIRECTORY {
//    DWORD   Characteristics;
//    DWORD   TimeDateStamp;
//    WORD    MajorVersion;
//    WORD    MinorVersion;
//    DWORD   Name;
//    DWORD   Base;
//    DWORD   NumberOfFunctions;
//    DWORD   NumberOfNames;
//    DWORD   AddressOfFunctions;     // RVA from base of image
//    DWORD   AddressOfNames;         // RVA from base of image
//    DWORD   AddressOfNameOrdinals;  // RVA from base of image
//} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
//
//#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
//
//typedef struct _IMAGE_OPTIONAL_HEADER {
//    //
//    // Standard fields.
//    //
//
//    WORD    Magic;
//    BYTE    MajorLinkerVersion;
//    BYTE    MinorLinkerVersion;
//    DWORD   SizeOfCode;
//    DWORD   SizeOfInitializedData;
//    DWORD   SizeOfUninitializedData;
//    DWORD   AddressOfEntryPoint;
//    DWORD   BaseOfCode;
//    DWORD   BaseOfData;
//
//    //
//    // NT additional fields.
//    //
//
//    DWORD   ImageBase;
//    DWORD   SectionAlignment;
//    DWORD   FileAlignment;
//    WORD    MajorOperatingSystemVersion;
//    WORD    MinorOperatingSystemVersion;
//    WORD    MajorImageVersion;
//    WORD    MinorImageVersion;
//    WORD    MajorSubsystemVersion;
//    WORD    MinorSubsystemVersion;
//    DWORD   Win32VersionValue;
//    DWORD   SizeOfImage;
//    DWORD   SizeOfHeaders;
//    DWORD   CheckSum;
//    WORD    Subsystem;
//    WORD    DllCharacteristics;
//    DWORD   SizeOfStackReserve;
//    DWORD   SizeOfStackCommit;
//    DWORD   SizeOfHeapReserve;
//    DWORD   SizeOfHeapCommit;
//    DWORD   LoaderFlags;
//    DWORD   NumberOfRvaAndSizes;
//    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
//
//typedef struct _IMAGE_FILE_HEADER {
//    WORD    Machine;
//    WORD    NumberOfSections;
//    DWORD   TimeDateStamp;
//    DWORD   PointerToSymbolTable;
//    DWORD   NumberOfSymbols;
//    WORD    SizeOfOptionalHeader;
//    WORD    Characteristics;
//} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
//
//typedef struct _IMAGE_NT_HEADERS {
//    DWORD Signature;
//    IMAGE_FILE_HEADER FileHeader;
//    IMAGE_OPTIONAL_HEADER OptionalHeader;
//} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
//
//#pragma warning( pop )
//#pragma pack( pop )

#ifdef _RING3_TEST

DWORD get_func_addr( char* func_name, USHORT order, DWORD module_base ); 

typedef HMODULE ( _stdcall *LOAD_LIBRARYW )( LPWSTR module_name ); 
ULONG get_mod_base( PDRIVER_OBJECT driver_obj, WCHAR *module_name, ULONG name_len )
{
	HMODULE dep_mod; 
	HMODULE kern_mod; 
	LOAD_LIBRARYW load_mod_func; 

	CHAR load_mod_func_name[20]; 
	*( PDWORD )load_mod_func_name = 'daoL'; 
	*( ( PDWORD )load_mod_func_name + 1 ) = 'rbiL'; 
	*( ( PDWORD )load_mod_func_name + 2 ) = 'Wyra'; 
	*( ( PDWORD )load_mod_func_name + 3 ) = 0; 

	kern_mod = ( HMODULE )get_kernel32_mod_base(); 
	load_mod_func = ( LOAD_LIBRARYW )get_func_addr( ( CHAR* )load_mod_func_name, INVALID_EXPORT_ORDER, ( ULONG )kern_mod ); 
	dep_mod = load_mod_func( module_name ); 

	return ( ULONG )( PVOID )dep_mod; 
}
#else
ULONG get_mod_base( PDRIVER_OBJECT driver_obj, WCHAR *module_name, ULONG name_len )
{
	LIST_ENTRY *entry = NULL;
	LDR_DATA_TABLE_ENTRY *ldr_entry = NULL;

	entry = ( ( LIST_ENTRY* )driver_obj->DriverSection )->Flink;

	do
	{
		ldr_entry = CONTAINING_RECORD( entry, 
			LDR_DATA_TABLE_ENTRY, 
			InLoadOrderLinks );

		if( ldr_entry->EntryPoint && 
			ldr_entry->BaseDllName.Buffer &&
			ldr_entry->FullDllName.Buffer && 
			ldr_entry->LoadCount )
		{
			if( name_len > ldr_entry->BaseDllName.Length )
			{
				name_len = ldr_entry->BaseDllName.Length; 
			}

			if( inline_wstrcmp( module_name, ldr_entry->BaseDllName.Buffer, name_len ) == 0 )
			{
				return ( DWORD )ldr_entry->DllBase;
			}
		}

		entry = entry->Flink;
	}
	while ( entry != ( ( LIST_ENTRY* )driver_obj->DriverSection )->Flink );

	return 0;
}
#endif

DWORD get_func_addr( CHAR* func_name, USHORT order, DWORD module_base )
{
	PIMAGE_DOS_HEADER dos_hdr;
	PIMAGE_NT_HEADERS nt_hdr;
	PIMAGE_EXPORT_DIRECTORY export_tbl;
	DWORD *func_addrs;
	DWORD *func_names;
	WORD *func_ords;
	DWORD export_base, i;
	char *_func_name;
	DWORD _func_ord;
	DWORD func_addr;
	
	if( func_name == NULL && 
		order == 0xffff )
	{
		ASSERT( FALSE ); 
		return NULL; 
	}

	dos_hdr = ( PIMAGE_DOS_HEADER )module_base;
	nt_hdr = ( PIMAGE_NT_HEADERS )( module_base + dos_hdr->e_lfanew );

	export_tbl = ( PIMAGE_EXPORT_DIRECTORY )( module_base + nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
	func_addrs = ( DWORD* )( module_base + export_tbl->AddressOfFunctions );
	func_names = ( DWORD* )( module_base + export_tbl->AddressOfNames );
	func_ords = ( WORD* )( module_base + export_tbl->AddressOfNameOrdinals );

	export_base = export_tbl->Base;

	for( i = 0; i < export_tbl->NumberOfNames; i++ )
	{
		_func_name = ( char* )( module_base + func_names[ i ] );
		_func_ord = func_ords[ i ];

		if( func_name != NULL )
		{
			if( inline_strcmp( _func_name, func_name ) == 0 )
			{
				goto _ret_addr; 
			}
		}
		else if( order != 0xffff )
		{
			if( _func_ord == order )
			{
				goto _ret_addr; 
			}
		}

		continue; 

_ret_addr:
		func_addr = module_base + func_addrs[ _func_ord ];
		return func_addr;
	}

	return 0;
}

//
//typedef struct __IMAGE_BASE_RELOCATION 
//{
//	DWORD   VirtualAddress;
//	DWORD   SizeOfBlock;
//	WORD    TypeOffset[1];
//} IMAGE_BASE_RELOCATION; 
//typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
//
//mov  eax,dword ptr [ebp+OriginalRelocateAddr]
//add  eax,dword ptr [ebp+ModuleHandle]
//mov  ecx,dword ptr [ebp+OriginalRelocateSize]
//mov  ebx,eax
//mov  esi,dword ptr [ebp+ModuleHandle]
//sub  esi,dword ptr [ebp+OriginalBaseAddr] ;esi=diff
//
//NextRelocateBlock:
//.if ecx == 0
//jmp FixAllRelocate
//.endif
//assume ebx : ptr IMAGE_BASE_RELOCATION
//push ecx
//mov  ecx,dword ptr [ebx].SizeOfBlock
//sub  ecx,sizeof IMAGE_BASE_RELOCATION
//shr  ecx,1
//mov  eax,ebx
//add  eax,sizeof IMAGE_BASE_RELOCATION
//NextRelocateEntry:
//xor edi,edi
//mov di,word ptr [eax]
//shr edi,12
//.if edi == IMAGE_REL_BASED_HIGHLOW
//movzx edi,word ptr [eax]
//and edi,0fffh
//add edi,dword ptr [ebx].VirtualAddress
//add edi,dword ptr [ebp+ModuleHandle]
//add dword ptr [edi],esi
//.endif
//add eax,2
//loop NextRelocateEntry
//pop  ecx
//sub  ecx,dword ptr [ebx].SizeOfBlock
//add  ebx,dword ptr [ebx].SizeOfBlock
//jmp NextRelocateBlock
//FixAllRelocate:
//

INT32 __stdcall restore_reloc( PIMAGE_BASE_RELOCATION base_reloc, DWORD unpack_image_base, DWORD org_pack_image_base_rec, PDRIVER_OBJECT driver_obj )
{
	PDWORD reloc_addr;
	INT32 count;
	INT32 type;
	INT32 i; 
	DWORD dep_module_base; 

#ifdef _PRINT_DEBUG
	DBG_PRINT print_func;
#endif

	dep_module_base = get_mod_base( driver_obj, 
		( WCHAR* )relocate_addr_in_other_image( depend_module ), 
		sizeof( depend_module ) ); 

	if( dep_module_base == 0 )
	{
		dep_module_base = get_mod_base( driver_obj, 
			( WCHAR* )relocate_addr_in_other_image( depend_module_other ), 
			sizeof( depend_module_other ) ); 

		if( dep_module_base == 0 )
		{
			return -1;
		}
	}

#ifdef _PRINT_DEBUG
	print_func = ( DBG_PRINT )get_func_addr( ( CHAR* )relocate_addr_in_other_image( dbg_print_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( print_func == NULL )
	{
		return -1;
	}

	print_func( ( CHAR* )relocate_addr_in_other_image( &print_image_base_diff ), 
		org_pack_image_base_rec, 
		unpack_image_base, 
		unpack_image_base  - org_pack_image_base_rec ); 
#endif

	while( base_reloc->SizeOfBlock )
	{
		count = base_reloc->SizeOfBlock / 2;
		
		for( i = 0; i < count; i++ )
		{
			type = base_reloc->TypeOffset[ i ] >> 0x0c; 

#ifdef _PRINT_DEBUG
			print_func( ( CHAR* )relocate_addr_in_other_image( print_reloc_offset ), 
				type, 
				base_reloc->VirtualAddress, 
				( DWORD )( base_reloc->TypeOffset[ i ] & 0x0fff ), 
				unpack_image_base ); 
#endif
			if( type == 3 )
			{
		
				if( ( DWORD )( base_reloc->TypeOffset[ i ] & 0x0fff ) == 0 )
				{
#ifdef _PRINT_DEBUG
					print_func( ( CHAR* )relocate_addr_in_other_image( print_reloc_is_zero ), i ); 
#endif
					break; 
				}

				reloc_addr = ( PDWORD )( ( DWORD )( base_reloc->TypeOffset[ i ] & 0x0fff ) + base_reloc->VirtualAddress + unpack_image_base );

#ifdef _PRINT_DEBUG
				print_func( ( CHAR* )relocate_addr_in_other_image( &print_reloc_diff ), 
					reloc_addr, 
					*reloc_addr, 
					*reloc_addr + ( unpack_image_base - org_pack_image_base_rec ) ); 
#endif
				*reloc_addr = *reloc_addr + ( unpack_image_base - org_pack_image_base_rec ); 
			}  
		}

		base_reloc = ( PIMAGE_BASE_RELOCATION )( ( DWORD )base_reloc + base_reloc->SizeOfBlock );
	}

	return 0; 
}


INT32 _stdcall decode_import_tbl( PBYTE import_codes, PDRIVER_OBJECT driver_obj, PBYTE unpack_image )
{
	int name_len = 0; //dll名或者函数名长度
	PDWORD first_thunk;
	DWORD func_count;
	DWORD func_addr;
	DWORD dep_module_base; 
#ifdef _PRINT_DEBUG
	DBG_PRINT print_func; 
#endif

	WCHAR *dll_name;
	DWORD j; 

	dep_module_base = get_mod_base( driver_obj, ( WCHAR* )relocate_addr_in_other_image( depend_module ), sizeof( depend_module ) );

	if( dep_module_base == 0 )
	{
		dep_module_base = get_mod_base( driver_obj, 
			( WCHAR* )relocate_addr_in_other_image( depend_module_other ), 
			sizeof( depend_module_other ) ); 

		if( dep_module_base == 0 )
		{
			return -1;
		}
	}

#ifdef _PRINT_DEBUG
	print_func = ( DBG_PRINT )get_func_addr( ( CHAR* )relocate_addr_in_other_image( dbg_print_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( print_func == NULL )
	{
		return -1;
	}
#endif

	for( ; ; )
	{
		if( *( DWORD* )import_codes == 0 )
		{
			break;
		}
	
		first_thunk = ( PDWORD )( *( DWORD* )import_codes + unpack_image );
		import_codes += sizeof( ULONG );

		name_len = *( BYTE* )import_codes;
		import_codes += sizeof( BYTE );
		
		dll_name = ( WCHAR* )import_codes; 
		dep_module_base = get_mod_base( driver_obj, dll_name, 10 );

		if( NULL == dep_module_base )
		{
#ifdef _PRINT_DEBUG
			print_func( ( CHAR* )relocate_addr_in_other_image( print_get_mod_base_err ), dll_name ); 
#endif
			//dep_module_base = get_mod_base( driver_obj, 
			//	( WCHAR* )relocate_addr_in_other_image( depend_module_other ), 
			//	sizeof( depend_module_other ) ); 

			//if( dep_module_base == 0 )
			//{
				return -1;
			//}
		}

		import_codes += name_len;

		func_count = *( DWORD* )import_codes;
		import_codes += sizeof( ULONG );  

		for( j = 0; j < func_count; j++ )
		{
			name_len = *( BYTE* )import_codes;
			if( name_len == 0 )
			{
				import_codes ++;

				func_addr = get_func_addr( NULL, *( PULONG )import_codes, dep_module_base );
				if( NULL == func_addr )
				{
#ifdef _PRINT_DEBUG
					print_func( ( CHAR* )relocate_addr_in_other_image( print_get_func_by_order_err ), *( PULONG )import_codes ); 
#endif
					return -1; 
				}

#ifdef _PRINT_DEBUG
				print_func( ( CHAR* )relocate_addr_in_other_image( print_get_func_addr_by_order ), 
					*( PULONG )import_codes, func_addr, first_thunk ); 
#endif

				*first_thunk = func_addr;
				first_thunk ++;
				import_codes += 4;
			}
			else
			{
				import_codes ++;

				func_addr = get_func_addr( ( CHAR* )import_codes, INVALID_EXPORT_ORDER, dep_module_base );
				if( NULL == func_addr )
				{
#ifdef _PRINT_DEBUG
					print_func( ( CHAR* )relocate_addr_in_other_image( print_get_func_by_name_err ), ( CHAR* )import_codes ); 
#endif
					return -1; 
				}

#ifdef _PRINT_DEBUG
				print_func( ( CHAR* )relocate_addr_in_other_image( print_get_func_addr_by_name ),
					( CHAR* )import_codes, func_addr, first_thunk ); 
#endif
				*first_thunk = func_addr;
				import_codes += name_len;
				first_thunk ++;
			}
		}
	}

	return 0;
}

#pragma warning( push )
#pragma warning( disable:4731 )
#ifdef __cplusplus
extern "C"
{
#endif

#ifdef _RING3_TEST
INT32 __stdcall test_ring3()
{
	INT32 ret; 
	DWORD dep_module_base; 
	HMODULE dep_module; 
	ALLOC_MEM mem_alloc_func; 
	FREE_MEM mem_free_func; 

#ifdef _PRINT_DEBUG
	DBG_PRINT print_func; 
#endif
	ret = 0; 
	dep_module = LoadLibraryW( depend_module ); 

	if( NULL == dep_module )
	{
		ret = -1; 
		goto _return; 
	}

	dep_module_base = ( DWORD )( PVOID )depend_module;

	if( depend_module == NULL )
	{
		ret = -1; 
		goto _return; 
	}

	mem_alloc_func = ( ALLOC_MEM )get_func_addr( ( CHAR* )relocate_addr_in_other_image( mem_alloc_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( mem_alloc_func == NULL )
	{
		ret = -1; 
		goto _return; 
	}
	
	mem_free_func = ( FREE_MEM )get_func_addr( ( CHAR* )relocate_addr_in_other_image( mem_free_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( mem_free_func == NULL )
	{
		ret = -1; 
		goto _return; 
	}

#ifdef _PRINT_DEBUG
    print_func = ( DBG_PRINT )get_func_addr( ( CHAR* )relocate_addr_in_other_image( dbg_print_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( print_func == NULL )
	{
		ret = -1; 
		goto _return; 
	}
#endif
	//print_func( relocate_addr_in_other_image( "ring3 functions is loaded \n" ) ); 

	ret = 0; 

_return:
	FreeLibrary( dep_module ); 
	return ret; 
}
#endif

#ifndef _RING3_TEST

INLINE DWORD _stdcall get_main_mod_base( PDRIVER_OBJECT driver_obj ) 
{
	return ( DWORD )driver_obj->DriverStart; 
}

#else

INLINE DWORD _stdcall get_main_mod_base( PDRIVER_OBJECT driver_obj ) 
{
	HMODULE dep_mod; 
	HMODULE kern_mod; 
	LOAD_LIBRARYW load_mod_func; 

	CHAR load_mod_func_name[22] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'W', '\0' }; 

	kern_mod = ( HMODULE )get_kernel32_mod_base(); 
	load_mod_func = ( LOAD_LIBRARYW )get_func_addr( ( CHAR* )load_mod_func_name, INVALID_EXPORT_ORDER, ( ULONG )kern_mod ); 
	dep_mod = load_mod_func( NULL ); 

	return ( ULONG )( PVOID )dep_mod; 
}

#endif

//IopLoadDriver+0x669

VOID __stdcall pack_driver_unload( PDRIVER_OBJECT driver_obj )
{
	driver_unload _unpack_mod_unload; 
	PVOID _unpack_mod; 
#ifdef _PRINT_DEBUG
	DBG_PRINT print_func;
#endif
	FREE_MEM mem_free_func; 
	DWORD dep_module_base; 

	//__asm int 3; 
	dep_module_base = get_mod_base( driver_obj, ( WCHAR* )relocate_addr_in_other_image( depend_module ), sizeof( depend_module ) );

	if( dep_module_base == 0 )
	{
		dep_module_base = get_mod_base( driver_obj, 
			( WCHAR* )relocate_addr_in_other_image( depend_module_other ), 
			sizeof( depend_module_other ) ); 

		if( dep_module_base == 0 )
		{
			goto unload_unpack_mod; 
		}
	}

	mem_free_func = ( FREE_MEM )get_func_addr( ( CHAR* )relocate_addr_in_other_image( mem_free_func_name ), INVALID_EXPORT_ORDER, dep_module_base );

#ifdef _PRINT_DEBUG
	print_func = ( DBG_PRINT )get_func_addr( ( CHAR* )relocate_addr_in_other_image( dbg_print_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
#endif

unload_unpack_mod:
	_unpack_mod_unload = *( driver_unload* )relocate_addr_in_other_image( &pack_mod_unload ); 
	if( _unpack_mod_unload == NULL )
	{
		return; 
	}

#ifdef _PRINT_DEBUG
	if( print_func != NULL )
	{
		print_func( ( CHAR* )relocate_addr_in_other_image( print_call_unpack_mod_unload ), _unpack_mod_unload ); 
	}
#endif

	_unpack_mod_unload( driver_obj ); 

_unload_release:
	_unpack_mod = *( PVOID * )relocate_addr_in_other_image( &unpacked_image ); 
	if( NULL == _unpack_mod )
	{
		
#ifdef _PRINT_DEBUG
		if( print_func != NULL )
		{
			print_func( ( CHAR* )relocate_addr_in_other_image( print_unpack_img_no_record ) );
		}
#endif

		return; 
	}

#ifdef _PRINT_DEBUG
	if( print_func != NULL )
	{
		print_func( ( CHAR* )relocate_addr_in_other_image( print_free_unpack_img ), _unpack_mod ); 
	}
#endif 

	if( mem_free_func != NULL )
	{
		mem_free_func( _unpack_mod ); 
	}

#ifdef _PRINT_DEBUG
	if( print_func != NULL )
	{
		print_func( ( CHAR* )relocate_addr_in_other_image( print_all_released ) ); 
	}
#endif 

}

#define MAX_PATH 260

//ZwClose
//ZwWriteFile
//ZwCreateFile
//RtlFreeUnicodeString
//RtlAppendUnicodeStringToString
//RtlAnsiStringToUnicodeString
//RtlInitAnsiString
//RtlCopyUnicodeString

INT32 __stdcall WriteBufferToFile( CHAR *FileName, UINT8 *Buf, INT32 WriteLen, PDRIVER_OBJECT driver_obj )
{
	NTSTATUS ntstatus;
	ANSI_STRING AnsiPostfix;
	UNICODE_STRING UniFileName;
	UNICODE_STRING UniPostfix;
	//UNICODE_STRING UniPrefix = RTL_CONSTANT_STRING(L"\\??\\");
	WCHAR *pUnicodeBuf = NULL;

	INT32 nRes = 0;
	//ULONG UniStrLen;
	OBJECT_ATTRIBUTES ObjectAttr;
	IO_STATUS_BLOCK IOStatusBlock;
	HANDLE hFileHandle = NULL;
	LARGE_INTEGER FileOffset;
	ALLOC_MEM mem_alloc_func;
	FREE_MEM mem_free_func;
#ifdef _PRINT_DEBUG
	DBG_PRINT print_func; 
#endif
	ZW_CLOSE zw_close_func; 
	ZW_WRITE_FILE zw_write_func; 
	ZW_CREATE_FILE zw_create_func; 
	RTL_FREE_UNICODE_STRING free_unicode_func;
	RTL_APPEND_UNICODE_STRING_TO_STRING append_unicode_func; 
	RTL_ANSI_STRING_TO_UNICODE_STRING ansi_to_unicode_func; 
	RTL_INIT_ANSI_STRING init_ansi_func;
	RTL_COPY_UNICODE_STRING copy_unicode_func; 
	DWORD dep_module_base; 

	//__asm int 3; 
	dep_module_base = get_mod_base( driver_obj, ( WCHAR* )relocate_addr_in_other_image( depend_module ), sizeof( depend_module ) );

	if( dep_module_base == 0 )
	{
		dep_module_base = get_mod_base( driver_obj, 
			( WCHAR* )relocate_addr_in_other_image( depend_module_other ), 
			sizeof( depend_module_other ) ); 

		if( dep_module_base == 0 )
		{
			nRes = -1; 
			goto _return; 
		}
	}

	mem_alloc_func = ( ALLOC_MEM )get_func_addr( ( CHAR* )relocate_addr_in_other_image( mem_alloc_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( mem_alloc_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	mem_free_func = ( FREE_MEM )get_func_addr( ( CHAR* )relocate_addr_in_other_image( mem_free_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( mem_free_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

#ifdef _PRINT_DEBUG
	print_func = ( DBG_PRINT )get_func_addr( ( CHAR* )relocate_addr_in_other_image( dbg_print_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( print_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}
#endif

	zw_close_func = ( ZW_CLOSE )get_func_addr( ( CHAR* )relocate_addr_in_other_image( close_file_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( zw_close_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	zw_write_func = ( ZW_WRITE_FILE )get_func_addr( ( CHAR* )relocate_addr_in_other_image( write_file_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( zw_write_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	zw_create_func = ( ZW_CREATE_FILE )get_func_addr( ( CHAR* )relocate_addr_in_other_image( create_file_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( zw_create_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	free_unicode_func = ( RTL_FREE_UNICODE_STRING )get_func_addr( ( CHAR* )relocate_addr_in_other_image( free_uni_str_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( free_unicode_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	append_unicode_func = ( RTL_APPEND_UNICODE_STRING_TO_STRING )get_func_addr( ( CHAR* )relocate_addr_in_other_image( append_uni_str_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( append_unicode_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	ansi_to_unicode_func = ( RTL_ANSI_STRING_TO_UNICODE_STRING )get_func_addr( ( CHAR* )relocate_addr_in_other_image( ansi_to_uni_str_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( ansi_to_unicode_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	init_ansi_func = ( RTL_INIT_ANSI_STRING )get_func_addr( ( CHAR* )relocate_addr_in_other_image( init_ansi_str_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( init_ansi_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

	copy_unicode_func = ( RTL_COPY_UNICODE_STRING )get_func_addr( ( CHAR* )relocate_addr_in_other_image( copy_uni_str_func_name ), INVALID_EXPORT_ORDER, dep_module_base ); 
	if( copy_unicode_func == NULL )
	{
		nRes = -1; 
		goto _return; 
	}

#ifdef _PRINT_DEBUG
	print_func( ( CHAR* )relocate_addr_in_other_image( print_enter_write_func ) ); 
#endif

	FileOffset.QuadPart = 0;

	pUnicodeBuf = (WCHAR*)mem_alloc_func(NonPagedPool, sizeof(WCHAR) * MAX_PATH );
	if(pUnicodeBuf == NULL)
	{
#ifdef _PRINT_DEBUG
		print_func( ( CHAR* )relocate_addr_in_other_image(print_alloc_name_buff_err));
#endif
		nRes = -1;
		goto _return;
	}

	RtlInitEmptyUnicodeString(&UniFileName, pUnicodeBuf, sizeof(WCHAR) * MAX_PATH );
	//copy_unicode_func(&UniFileName, &UniPrefix);

	//if(!NT_SUCCESS(ntstatus))
	//{
	//	PrintMsg(1, ("Copy device path prefix error"));
	//	nRes = 1;
	//	goto _return;
	//}

	init_ansi_func(&AnsiPostfix, FileName);
	ntstatus = ansi_to_unicode_func(&UniPostfix, &AnsiPostfix, TRUE);
	//UniStrLen = RtlAnsiStringToUnicodeSize(&AnsiFileName);
	if(!NT_SUCCESS(ntstatus))
	{
#ifdef _PRINT_DEBUG
		print_func( ( CHAR* )relocate_addr_in_other_image( print_conv_name_err ) );
#endif
		nRes = -2;
		goto _return;
	}

	ntstatus = append_unicode_func(&UniFileName, &UniPostfix); 
	free_unicode_func(&UniPostfix);

	if(!NT_SUCCESS(ntstatus))
	{
#ifdef _PRINT_DEBUG
		print_func( ( CHAR* )relocate_addr_in_other_image( print_conv_name_err ) );
#endif
		nRes = -3;
		goto _return;
	}

	InitializeObjectAttributes(&ObjectAttr, &UniFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ntstatus = zw_create_func(&hFileHandle, 
		FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE, 
		&ObjectAttr,
		&IOStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
 		FILE_OPEN_IF,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	if(!NT_SUCCESS(ntstatus))
	{
#ifdef _PRINT_DEBUG
		print_func( ( CHAR* )relocate_addr_in_other_image(print_open_file_err ));
#endif
		nRes = -5;
		goto _return;
	}

	ntstatus = zw_write_func(hFileHandle,
		NULL, 
		NULL, 
		NULL, 
		&IOStatusBlock, 
		(PVOID)Buf, 
		(ULONG)WriteLen, 
		&FileOffset,
		NULL);

	if(!NT_SUCCESS(ntstatus))
	{
#ifdef _PRINT_DEBUG
		print_func( ( CHAR* )relocate_addr_in_other_image(print_write_file_err ));
#endif
		nRes = -6;
		goto _return;
	}

#ifdef _PRINT_DEBUG
	print_func( ( CHAR* )relocate_addr_in_other_image(print_exit_write_buff ) );
#endif

	nRes = 0; 
_return:
	if(pUnicodeBuf != NULL)
		mem_free_func(pUnicodeBuf);

	if(hFileHandle != NULL)
		zw_close_func(hFileHandle);
	return nRes;
}

NTSTATUS __stdcall DriverEntry( IN PDRIVER_OBJECT driver_obj, IN PUNICODE_STRING reg_path )
{
	INT32 ret; 
	NTSTATUS ntstatus; 
	ALLOC_MEM mem_alloc_func;
	FREE_MEM mem_free_func; 
#ifdef _PRINT_DEBUG
	DBG_PRINT print_func; 
#endif
	DWORD dep_module_base; 
	DWORD image_base; 
	PBYTE unpack_image = NULL; 
	PBYTE unpack_section; 
	PBYTE packed_data; 
	PPACKET_INFO pack_info; 
	PBYTE import_codes; 
	DWORD org_entry_ptr; 
	INT32 i; 
	ULONG _Cr0Reg;
	ULONG Cr0Reg; 
	KSPIN_LOCK sp_lock = 0; 
	KIRQL old_irql; 

	( reg_path );

	//__asm int 3 ; 

	//_try 
	//{ 
	//	__asm
	//	{
	//		mov eax, 0; 
	//		mov dword ptr [ eax ], 0; 
	//	}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	dep_module_base = get_mod_base( driver_obj, ( WCHAR* )relocate_addr_in_other_image( depend_module ), sizeof( depend_module ) );
	//}

	dep_module_base = get_mod_base( driver_obj, ( WCHAR* )relocate_addr_in_other_image( depend_module ), sizeof( depend_module ) );

	if( dep_module_base == 0 )
	{
		dep_module_base = get_mod_base( driver_obj, 
			( WCHAR* )relocate_addr_in_other_image( depend_module_other ), 
			sizeof( depend_module_other ) ); 

		if( dep_module_base == 0 )
		{
			ntstatus = STATUS_UNSUCCESSFUL; 
			goto _return; 
		}
	}

	ntstatus = STATUS_SUCCESS; 

	mem_alloc_func = ( ALLOC_MEM )get_func_addr( ( CHAR* )relocate_addr_in_other_image( mem_alloc_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( mem_alloc_func == NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 

	}

	mem_free_func = ( FREE_MEM )get_func_addr( ( CHAR* )relocate_addr_in_other_image( mem_free_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( mem_free_func == NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

#ifdef _PRINT_DEBUG
	print_func = ( DBG_PRINT )get_func_addr( ( CHAR* )relocate_addr_in_other_image( dbg_print_func_name ), INVALID_EXPORT_ORDER, dep_module_base );
	if( print_func == NULL )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}
#endif

#ifdef _PRINT_DEBUG
	print_func( ( CHAR* )relocate_addr_in_other_image( print_banner ) ); 
#endif

	image_base = get_main_mod_base( driver_obj );

	//申请内存空间
#ifdef _RING3_TEST
	unpack_image = ( BYTE* )mem_alloc_func( *( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_SIZE ] ) );
#else
	unpack_image = ( BYTE* )mem_alloc_func( NonPagedPool, *( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_SIZE ] ) );
#endif

	if( NULL == unpack_image )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

#ifdef _PRINT_DEBUG
	print_func( ( CHAR* )relocate_addr_in_other_image( print_sys_img_info ), image_base, 
		*( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_SIZE ] ), 
		unpack_image ); 
#endif

	inline_memset( unpack_image, 0, *( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_SIZE ] ) );
	//unpack_section = unpack_image;

	//得到保存压缩数据的节的地址
	unpack_image = ( PBYTE )( *( DWORD* )relocate_addr_in_other_image( &shell_infos[ UNPACK_SPACE_RVA ] ) + image_base );
	packed_data = ( PBYTE )( *( DWORD* )relocate_addr_in_other_image( &shell_infos[ PACKET_DATA_RVA ] ) + image_base );
	pack_info = ( PPACKET_INFO )relocate_addr_in_other_image( pack_infos ); 

	#define W_PROTECT_BIT_MASK 0xFFFEFFFF
	__asm
	{
		mov eax, cr0;
		mov dword ptr [ _Cr0Reg ], eax;
		and eax, W_PROTECT_BIT_MASK;
		mov cr0, eax;
		cli;
		mov eax, dword ptr [ _Cr0Reg ];
		mov dword ptr [ Cr0Reg ], eax;
	}

	for( i = 0; i < ARRAY_SIZE( pack_infos ); i++ )
	{
		if(  pack_info[ i ].vsize == 0 )
			break;

#ifdef _PRINT_DEBUG
		print_func( ( CHAR* )relocate_addr_in_other_image( print_sys_pack_info ), 
			pack_info[ i ].vaddr, 
			pack_info[ i ].vsize, 
			pack_info[ i ].packed_size, 
			pack_info[ i ].unpack_size ); 
#endif

		unpack_section = unpack_image + pack_info[ i ].vaddr; 
		aP_depack_safe( packed_data, pack_info[ i ].packed_size, unpack_section, pack_info[ i ].unpack_size );
		packed_data += pack_info[ i ].packed_size; 
	}

	//for( i = 0; i < ARRAY_SIZE( pack_infos ); i ++ )
	//{
	//	switch( i )
	//	{
	//	case OLD_IMAGE_SIZE:
	//		{
	//			print_func( ( CHAR* )relocate_addr_in_other_image( print_old_img_size ), 
	//				*( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_SIZE ] ) ); 
	//		}
	//		break; 
	//	case PACKET_DATA_RVA:
	//		{
	//			print_func( "PACKET_DATA_RVA: %d \n", 
	//				*( DWORD* )relocate_addr_in_other_image( &shell_infos[ PACKET_DATA_RVA ] ) ); 
	//		}
	//		break; 
	//	case IMPORT_RVA:
	//		{
	//			print_func( "IMPORT_RVA: %d \n", 
	//				*( DWORD* )relocate_addr_in_other_image( &shell_infos[ IMPORT_RVA ] ) ); 
	//		}
	//		break; 
	//	case RELOC_RVA:
	//		{
	//			print_func( "RELOC_RVA: %d \n", 
	//				*( DWORD* )relocate_addr_in_other_image( &shell_infos[ RELOC_RVA ] ) ); 
	//		}
	//		break; 
	//	case OLD_IMAGE_BASE:
	//		{
	//			print_func( "OLD_IMAGE_BASE: %d \n", 
	//				*( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_BASE ] ) ); 
	//		}
	//		break; 
	//	case OEP:
	//		{
	//			print_func( "OEP: %d \n", 
	//				*( DWORD* )relocate_addr_in_other_image( &shell_infos[ OEP ] ) ); 
	//		}
	//		break; 
	//	default:
	//		break; 
	//	}
	//}

	import_codes = ( PBYTE )( *( DWORD* )relocate_addr_in_other_image( &shell_infos[ IMPORT_RVA ] ) + image_base );

	//_asm int 3; 

	ret = decode_import_tbl( import_codes, driver_obj, unpack_image );  
	if( ret < 0 )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	//int name_len = 0;
	//PDWORD first_thunk;
	//DWORD func_count;
	//DWORD func_addr;
	//while(TRUE)
	//{
	//	if(*(DWORD*)import_codes==0)
	//	{
	//		break;
	//	}
	//	print_func((char*)relocate_addr_in_other_image(data_fmt),*(DWORD*)import_codes);
	//	first_thunk=(PDWORD)(*(DWORD*)import_codes+unpack_image);
	//	//	DBGPRINT( ( "fist thunk:%X\n", *( DWORD* )import_codes ) );
	//	import_codes+=4;
	//	name_len=*(BYTE*)import_codes;
	//	//	DBGPRINT( ( "name_len:%d\n", name_len ) );
	//	import_codes++;

	//	//	DBGPRINT( ( "dll name:%s\n", (char*)import_codes ) );
	//	import_codes+=name_len;
	//	func_count=*(DWORD*)import_codes;
	//	//	DBGPRINT( ( "fun count:%d\n", func_count ) );
	//	import_codes+=4;  
	//	for( DWORD j = 0; j < func_count; j++ )
	//	{
	//		name_len=*(BYTE*)import_codes;
	//		if(name_len==0)
	//		{
	//			import_codes++;
	//			//	DBGPRINT( ( "index:%d\n", *( DWORD* )import_codes ) );
	//			first_thunk++;
	//			import_codes+=4;
	//		}
	//		else
	//		{
	//			import_codes++;
	//			func_addr=get_func_addr((char*)import_codes, INVALID_EXPORT_ORDER, dep_module_base);
	//			print_func((char*)relocate_addr_in_other_image(data_fmt),func_addr);
	//			*first_thunk=func_addr;
	//			//	DBGPRINT( ( "%s\n",( char* )import_codes ) );
	//			import_codes+=name_len;
	//			first_thunk++;
	//		}
	//	}
	//}

	//_asm int 3; 

	ret = restore_reloc( ( PIMAGE_BASE_RELOCATION )( *( DWORD* )relocate_addr_in_other_image( &shell_infos[ RELOC_RVA ] ) + ( DWORD )unpack_image ), 
		( DWORD )unpack_image, 
		*( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_BASE ] ), 
		driver_obj ); 
	if( ret < 0 )
	{
		ntstatus = STATUS_UNSUCCESSFUL; 
		goto _return; 
	}

	//WriteBufferToFile( ( CHAR* )relocate_addr_in_other_image( mod_dump_file_name ), 
	//	unpack_image, 
	//	*( DWORD* )relocate_addr_in_other_image( &shell_infos[ OLD_IMAGE_SIZE ] ), 
	//	driver_obj ); 

	org_entry_ptr = *( DWORD* )relocate_addr_in_other_image( &shell_infos[ OEP ] ) + ( DWORD )unpack_image;

	//_asm
	//{
	//	mov eax,org_entry_ptr;
	//	mov     esp, ebp;
	//	pop     ebp;
	//	int 3; 
	//	jmp eax;
	//}

	_asm
	{
		mov eax,org_entry_ptr;
		//int 3; 
		push dword ptr [ reg_path ]; 
		push dword ptr [ driver_obj ]; 
		call eax;
		mov dword ptr[ ntstatus ], eax; 
	}

	__asm
	{
		sti;
		mov eax, dword ptr [ Cr0Reg ];
		mov cr0, eax;
	}

	if( !NT_SUCCESS( ntstatus ) )
	{
		goto _return; 
	}

	*( PVOID* )relocate_addr_in_other_image( &unpacked_image ) = unpack_image; 
	*( driver_unload* )relocate_addr_in_other_image( &pack_mod_unload ) = driver_obj->DriverUnload; 
	//driver_obj->DriverUnload = ( driver_unload )relocate_addr_in_other_image( &pack_driver_unload ); 
	return ntstatus; 

_return:
	if( NULL != unpack_image )
	{
		mem_free_func( unpack_image ); 
	}

	return ntstatus; 
}

#ifdef __cplusplus
}
#endif
#pragma warning( pop )

/*
void create()
{
	MessageBox(NULL,end,end,0);
}
*/

#pragma code_seg()
