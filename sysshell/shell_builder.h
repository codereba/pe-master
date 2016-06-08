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

VOID __stdcall reloc_parse( PIMAGE_BASE_RELOCATION base_reloc, PBYTE img_base_to_loc )
{
	PDWORD reloc_addr;
	INT32 count;
	INT32 type;
	INT32 i; 

	while( base_reloc->SizeOfBlock )
	{
		count = base_reloc->SizeOfBlock / 2;
		
		DBGPRINT( ( "base reloc count is %d\n", count ) ); 

		for( i = 0; i < count; i++ )
		{
			type = base_reloc->TypeOffset[ i ] >> 0x0c;
			
			DBGPRINT( ( "base reloc type is %d\n", type ) ); 

			if( type == 3 )
			{
		
				reloc_addr = ( PDWORD )( ( DWORD )( base_reloc->TypeOffset[ i ] & 0x0fff ) + base_reloc->VirtualAddress + img_base_to_loc );

				DBGPRINT( ( "base reloc addr is 0x%0.8x\n", *reloc_addr ) ); 

				//*reloc_addr = *reloc_addr + ( unpack_image_base - org_pack_image_base_rec );
			}  
		}

		base_reloc = ( PIMAGE_BASE_RELOCATION )( ( DWORD )base_reloc + base_reloc->SizeOfBlock ); 
		DBGPRINT( ( "locate to next base reloc \n" ) ); 
	}
}

//typedef struct __IMAGE_BASE_RELOCATION 
//{
//	DWORD   VirtualAddress;
//	DWORD   SizeOfBlock;
//	WORD    TypeOffset[1];
//} IMAGE_BASE_RELOCATION; 
//typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;

INT32 build_reloc_table( PBYTE reloc_tbl, DWORD vaddr )
{
	PIMAGE_BASE_RELOCATION reloc; 
	INT32 count;
	INT32 offset;
	INT32 i; 

	reloc = ( PIMAGE_BASE_RELOCATION )reloc_tbl; 
	reloc->SizeOfBlock = 8; 
	reloc->VirtualAddress = vaddr; 

	count = 4;
	
	for( i = 0; i < count; i ++ )
	{
		reloc->TypeOffset[ i ] |= 0x03000000; 
	}

	offset = ( DWORD )&shell_infos - vaddr; 
	reloc->TypeOffset[ 0 ] |= ( offset & 0x00ffffff ); 
	
	offset = ( DWORD )&pack_infos - vaddr; 
	reloc->TypeOffset[ 1 ] |= ( offset & 0x00ffffff ); 
	
#ifdef _PRINT_DEBUG
	offset = ( DWORD )&dbg_print_func_name - vaddr; 
	reloc->TypeOffset[ 2 ] |= ( offset & 0x00ffffff ); 
#endif

	offset = ( DWORD )&depend_module - vaddr; 
	reloc->TypeOffset[ 3 ] |= ( offset & 0x00ffffff ); 
	return 0; 
}
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
INT32 gen_shell_code()
{
	INT32 ret; 
	DWORD writed;
	DWORD shell_code_size; 
	DWORD no_pack_res_addr; 
	DWORD shell_file_size; 
	DWORD shell_sect_size; 
	DWORD err_code; 

	shell_code_size = ( DWORD )end - ( DWORD )aP_getbit_safe; 

	DBGPRINT( ( "shellcode region: 0x%0.8x - 0x%0.8x size: %d\n",
		( DWORD )end, 
		( DWORD )aP_getbit_safe, 
		shell_code_size ) ); 
	
	get_img_res_dir(); 

	no_pack_res_addr = img_section_hdrs[ PACK_DATA_SECTION_INDEX ].VirtualAddress + img_section_hdrs[ PACK_DATA_SECTION_INDEX ].Misc.VirtualSize + shell_code_size + img_res_dir_size; 
	
	free( img_res_dir );

	reloc_type_res( 0x3, no_pack_res_addr );
	reloc_type_res( 0xe, no_pack_res_addr );
	reloc_type_res( 0x10, no_pack_res_addr );
	reloc_type_res( 0x18, no_pack_res_addr ); 

	get_img_res_dir();

	shell_infos[ IMPORT_RVA ] = img_section_hdrs[ PACK_DATA_SECTION_INDEX ].VirtualAddress + 
		img_section_hdrs[ PACK_DATA_SECTION_INDEX ].Misc.VirtualSize + 
		shell_code_size + 
		img_res_dir_size + 
		no_pack_res_size; 

	shell_file_size = shell_code_size + 
		img_res_dir_size + 
		no_pack_res_size + 
		import_codes_size; 

	img_section_hdrs[ SHELL_SECTION_INDEX ].Characteristics = PACK_FILE_SECTION_FLAGS;
	shell_sect_size = align( shell_file_size, img_file_align ); 

	img_section_hdrs[ SHELL_SECTION_INDEX ].SizeOfRawData = shell_sect_size; 
	img_section_hdrs[ SHELL_SECTION_INDEX ].Misc.VirtualSize = align( shell_file_size, img_section_align ); 

	strcpy( ( CHAR* )img_section_hdrs[ SHELL_SECTION_INDEX ].Name, ".ptxt" ); 

	img_section_hdrs[ SHELL_SECTION_INDEX ].VirtualAddress = img_section_hdrs[ PACK_DATA_SECTION_INDEX ].VirtualAddress + img_section_hdrs[ PACK_DATA_SECTION_INDEX ].Misc.VirtualSize;

	img_section_hdrs[ SHELL_SECTION_INDEX ].PointerToRawData = img_section_hdrs[ PACK_DATA_SECTION_INDEX ].PointerToRawData + img_section_hdrs[ PACK_DATA_SECTION_INDEX ].SizeOfRawData; 

	shell_infos[ OEP ] = img_nt_hdr->OptionalHeader.AddressOfEntryPoint; 
	img_nt_hdr->OptionalHeader.AddressOfEntryPoint = img_section_hdrs[ SHELL_SECTION_INDEX ].VirtualAddress; 
	img_nt_hdr->OptionalHeader.AddressOfEntryPoint += ( ( DWORD )( PVOID )DriverEntry -( DWORD )( PVOID )aP_getbit_safe );

	shell_infos[ RELOC_RVA ] = img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress; 

	reloc_parse( ( PIMAGE_BASE_RELOCATION )( img_base + shell_infos[ RELOC_RVA ] ), img_base ); 

#define ADDED_RELOC_SIZE 16
	img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress = 0;
	img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size = 0; //ADDED_RELOC_SIZE;
	
	img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ].VirtualAddress = 0; 
	img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG ].Size = 0; 

	//build_reloc_table( reloc_tbl, img_section_hdrs[ SHELL_SECTION_INDEX ].VirtualAddress ); 
	
	img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size = 0;
	img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress = 0;

	img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ].VirtualAddress = img_section_hdrs[ SHELL_SECTION_INDEX ].VirtualAddress + shell_code_size; 

	img_nt_hdr->OptionalHeader.SizeOfImage = img_section_hdrs[ SHELL_SECTION_INDEX ].VirtualAddress + img_section_hdrs[ SHELL_SECTION_INDEX ].Misc.VirtualSize; 
	
	{
		ULONG cur_pos; 
		cur_pos = SetFilePointer( packed_file, 0, NULL, SEEK_CUR ); 
		DBGPRINT( ( "current file position is %d\n", cur_pos ) ); 
	}

	if( !WriteFile( packed_file, aP_getbit_safe, shell_code_size, &writed, NULL ) )
	{
		err_code = GetLastError(); 

		DBGPRINT( ( "write shell failed\n" ) );  
		ret = FALSE; 
		goto _err_return; 
	}

	DBGPRINT( ( "shell code writed: %d, writed %d\n", shell_code_size, writed ) );
	
	if( !WriteFile( packed_file, img_res_dir, img_res_dir_size, &writed, NULL ) )
	{
		DBGPRINT( ( "write res dir failed\n" ) );
		err_code = GetLastError(); 

		ret = FALSE; 
		goto _err_return; 
	}

	DBGPRINT( ( "res dir writed :%d, writed: %d\n", img_res_dir_size, writed ) );
	
	if( !WriteFile( packed_file, no_pack_res, no_pack_res_size, &writed, NULL ) )
	{
		DBGPRINT( ( "write no pack res failed\n" ) );
		ret = FALSE; 
		goto _err_return; 
	}

	DBGPRINT( ( "cant packed res writed:%d writed %d \n", no_pack_res_size, writed ) );

	if( !WriteFile( packed_file, import_codes, import_codes_size, &writed, NULL ) )
	{
		DBGPRINT( ( "write no pack res failed\n" ) );
		ret = FALSE; 
		goto _err_return; 
	}

	DBGPRINT( ( "import code writed: %d writed: %d\n", import_codes_size, writed ) );
   
	if( shell_sect_size > shell_file_size )
	{
		PVOID zero; 
		zero = malloc( shell_sect_size - shell_file_size ); 
		memset( zero, 0, shell_sect_size - shell_file_size );
		if( !WriteFile( packed_file, zero, shell_sect_size - shell_file_size, &writed, NULL ) ) 
		{
			DBGPRINT( ( "write zero failed\n" ) );
			ret = FALSE; 
			goto _err_return; 
		}

		DBGPRINT( ( "writed appending data: %d writed: %d\n", shell_sect_size - shell_file_size, writed ) );
	}

	//write the pack data and shell sections in begin of the orginal file, finally.
	SetFilePointer( packed_file, 0, NULL, FILE_BEGIN );
	if( !WriteFile( packed_file, img_base, img_nt_hdr->OptionalHeader.SizeOfHeaders, &writed, NULL ) )
	{
		DBGPRINT( ( "write no pack res failed\n" ) );
		ret = FALSE; 
		goto _err_return; 
	}

	ret = TRUE; 

_err_return: 
	ASSERT( packed_file != INVALID_HANDLE_VALUE ); 
	CloseHandle( packed_file );
	return ret;
}
