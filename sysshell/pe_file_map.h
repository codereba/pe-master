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

INT32 validate_reloc_tbl( PIMAGE_BASE_RELOCATION reloc_tbl, ULONG img_vsize ) 
{
	INT32 i;
	INT32 ret; 

	ret = 0; 
	if( reloc_tbl->VirtualAddress == 0 )
	{
		if( reloc_tbl->SizeOfBlock == 0 )
		{
			goto _return; 
		}

		reloc_tbl->SizeOfBlock = 0; 
		ret = -1; 
		goto _return; 
	}

	for( i = 0; reloc_tbl->SizeOfBlock / sizeof( USHORT ); i ++ )
	{
		if( ( reloc_tbl->TypeOffset[ i ] >> 0xc ) > 10 )
		{
			reloc_tbl->SizeOfBlock = 0; 
			ret = -1; 
			goto _return; 
		}

		if( ( reloc_tbl->TypeOffset[ i ] & 0x0fff ) + reloc_tbl->VirtualAddress > img_vsize )
		{
			reloc_tbl->SizeOfBlock = 0; 
		}
	}

_return:
	DBGPRINT( ( "the reloc table of the pe image is invalid\n" ) ); 
	return ret; 
}

//把文件load进内存
BOOL map_pe_file( LPCSTR file_name )
{
	IMAGE_NT_HEADERS ntHeader;
	IMAGE_DOS_HEADER dosHeader;
	
	DWORD ntHeaderSize; 
	DWORD dwRead;
	DWORD RawDataSize  ;
	DWORD RawDataOffset;
	DWORD VirtualAddress;
	DWORD VirtualSize;
	DWORD first_sect_data_addr; 
	DWORD first_sect_index; 
	DWORD before_data_fill_ptr; 
	INT32 i;

	HANDLE hFile = CreateFile(
		file_name,
		GENERIC_READ,
		FILE_SHARE_READ, 
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) 
	{
		DBGPRINT( ( "open the file failed\n" ) );
		return FALSE;

	}

	//读取dos头部
	if( !ReadFile( hFile, &dosHeader, sizeof( IMAGE_DOS_HEADER ), &dwRead, NULL ) )
	{
		DBGPRINT( ( "read dos header failed\n" ) );
		CloseHandle(hFile);
		return FALSE;
	}
	//判断是不是pe文件
	if( dosHeader.e_magic != IMAGE_DOS_SIGNATURE )
	{
		DBGPRINT( ( "this is not a pe file\n" ) );
        CloseHandle(hFile);
		return FALSE;
	}

	//定位到nt头
	SetFilePointer( hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN );

	//读取nt头
	if(!ReadFile(hFile,&ntHeader,sizeof(IMAGE_NT_HEADERS),&dwRead,NULL))
	{
		DBGPRINT( ( "read nt header failed\n" ) );
		CloseHandle(hFile);
		return FALSE;
	}

	//判断是不是pe文件
	if( ntHeader.Signature != IMAGE_NT_SIGNATURE )
	{
		DBGPRINT( ( "this is not a pe file\n" ) );
		CloseHandle(hFile);
		return FALSE;
	}

	img_sect_num = ntHeader.FileHeader.NumberOfSections;
	img_load_base = ntHeader.OptionalHeader.ImageBase;
	//写入原映像基址，修复重定位时候要用
	shell_infos[ OLD_IMAGE_BASE ] = img_load_base;

	img_load_size = ntHeader.OptionalHeader.SizeOfImage;
	//写入原映像大小，壳中申请内存的时候要用
	shell_infos[ OLD_IMAGE_SIZE ] = img_load_size;
	img_file_align = ntHeader.OptionalHeader.FileAlignment;
	img_section_align = ntHeader.OptionalHeader.SectionAlignment;
	headerSize = ntHeader.OptionalHeader.SizeOfHeaders;

	//修正映像大小
	img_load_size = align( img_load_size, img_section_align );
	//申请映像内存
	img_base = ( PBYTE )VirtualAlloc( NULL, img_load_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE ); //malloc( img_load_size );
	memset( img_base, 0, img_load_size );

	SetFilePointer( hFile, 0, NULL,  FILE_BEGIN );
	
	//读取pe头部，（pe头部包括节表）
	if( !ReadFile( hFile, img_base, headerSize, &dwRead, NULL ) )
	{
		DBGPRINT( ( "read pe headers failed\n" ) );
		CloseHandle( hFile );
		return FALSE;
	}

	img_nt_hdr=( PIMAGE_NT_HEADERS )( img_base + dosHeader.e_lfanew );

	validate_reloc_tbl( ( PIMAGE_BASE_RELOCATION )( img_base + img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress ), img_load_size ); 

	//得到nt头部的大小
	ntHeaderSize = sizeof( ntHeader.FileHeader ) + sizeof( ntHeader.Signature ) + ntHeader.FileHeader.SizeOfOptionalHeader;
	
	//定位到节表
	img_section_hdrs = ( PIMAGE_SECTION_HEADER )( ( DWORD )img_nt_hdr + ntHeaderSize );

	before_data_fill_ptr = dosHeader.e_lfanew + 
		sizeof( IMAGE_FILE_HEADER ) + 
		sizeof( ntHeader.Signature ) + 
		ntHeader.FileHeader.SizeOfOptionalHeader + 
		ntHeader.FileHeader.NumberOfSections * 
		sizeof( IMAGE_SECTION_HEADER ); 


	if( headerSize != before_data_fill_ptr )
	{
		DBGPRINT( ( "invalid file format: the file header size wrote in the pe file %d is not equal to the real headers size %d \n", 
			headerSize, 
			before_data_fill_ptr ) ); 
		ASSERT( FALSE ); 
	}
	
	first_sect_data_addr = 0xffffffff; 
	first_sect_index = -1; 

	//修正节表信息
	for( i = 0 ; i < img_sect_num; i++ )
	{
		if( img_section_hdrs[ i ].PointerToRawData < first_sect_data_addr )
		{
			first_sect_data_addr = img_section_hdrs[ i ].PointerToRawData; 
			first_sect_index = i; 
		}

		RawDataSize = img_section_hdrs[i].SizeOfRawData;
		RawDataOffset = img_section_hdrs[i].PointerToRawData;
		VirtualAddress = img_section_hdrs[i].VirtualAddress;
		VirtualSize = img_section_hdrs[i].Misc.VirtualSize;
		
		//对齐
		img_section_hdrs[i].SizeOfRawData = align( RawDataSize,img_file_align );
		img_section_hdrs[i].Misc.VirtualSize = align( VirtualSize,img_section_align ); 
		if( RawDataSize != img_section_hdrs[i].SizeOfRawData )
		{
			DBGPRINT( ( "the corrected file size %d is different with the original file size of the section %d \n", 
				RawDataSize, 
				img_section_hdrs[i].SizeOfRawData ) ); 
			
			ASSERT( FALSE ); 
		}

		if( VirtualSize != img_section_hdrs[i].Misc.VirtualSize )
		{
			DBGPRINT( ( "the corrected virtual size %d is different with the original virtual size of the section %d \n", 
				RawDataSize, 
				img_section_hdrs[i].SizeOfRawData ) ); 

			ASSERT( FALSE ); 
		}

		//一般不会发生
		DBGPRINT( ( "all section file size %d, the image virtual space size %d \n", 
			img_section_hdrs[ i ].VirtualAddress + img_section_hdrs[i].SizeOfRawData, 
			img_load_size ) ); 

		if( i == img_sect_num - 1 && img_section_hdrs[ i ].VirtualAddress + img_section_hdrs[i].SizeOfRawData > img_load_size )
		{
			DBGPRINT( ( "all section file size %d is greater than the image virtual space size %d! \n", 
				img_section_hdrs[ i ].VirtualAddress + img_section_hdrs[i].SizeOfRawData, 
				img_load_size ) ); 

			img_section_hdrs[ i ].SizeOfRawData = img_load_size - img_section_hdrs[ i ].VirtualAddress;
			ASSERT( FALSE ); 
		}
	}

	if( headerSize != before_data_fill_ptr )
	{
		DBGPRINT( ( "invalid file format: the file header size wrote in the pe file %d is not equal to the real headers size %d \n", 
			headerSize, 
			before_data_fill_ptr ) ); 
		ASSERT( FALSE ); 

		if( first_sect_index != -1 )
		{
			if( img_section_hdrs[ first_sect_index ].PointerToRawData != headerSize )
			{
				ASSERT( FALSE );
				return FALSE; 
			}
		}
		else
		{
			ASSERT( FALSE ); 
			return FALSE; 
		}
	}

	if( first_sect_index != -1 )
	{
		ASSERT( img_section_hdrs[ first_sect_index ].VirtualAddress >= img_section_hdrs[ first_sect_index ].PointerToRawData ); 
		SetFilePointer( hFile, before_data_fill_ptr, 0, FILE_BEGIN ); 
		if( !ReadFile( hFile, img_base + before_data_fill_ptr, img_section_hdrs[ first_sect_index ].PointerToRawData - before_data_fill_ptr, &dwRead, NULL ) )
		{
			ASSERT( FALSE ); 
			DBGPRINT( ( "read the fill data before the first section failed \n" ) ); 
			return FALSE; 
		}
	}

	//读取各节数据
	for( i = 0; i < img_sect_num; i++ )
	{
		RawDataSize = img_section_hdrs[ i ].SizeOfRawData;
		RawDataOffset = img_section_hdrs[ i ].PointerToRawData;
		VirtualAddress = img_section_hdrs[ i ].VirtualAddress;
		VirtualSize = img_section_hdrs[ i ].Misc.VirtualSize;
		SetFilePointer( hFile, RawDataOffset, NULL, FILE_BEGIN );
		if( !ReadFile( hFile, &img_base[ VirtualAddress ], RawDataSize, &dwRead, NULL ) )
		{
			DBGPRINT( ("read section data filed\n" ) );
			CloseHandle( hFile );
			return FALSE;
		}
	}

	CloseHandle( hFile );
	return TRUE;
}

