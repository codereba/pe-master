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

#define REMOVE_DOS_FILL_DATA 1
#define OVERWRITE_SECTION_HEADER_TAIL_FILL_DATA 2
#define APPEND_NEW_SECTION_SPACE 3 
INT32 get_new_section_space( PBYTE *_data, ULONG *size, ULONG sect_size, ULONG flags )
{
	ULONG _size; 
	PBYTE data; 
	ULONG sect_hdrs_end;
	PIMAGE_DOS_HEADER dos_hdr; 
	PIMAGE_NT_HEADERS nt_hdrs; 
	PIMAGE_SECTION_HEADER sect_hdrs; 

	PIMAGE_SECTION_HEADER new_sect; 
	PIMAGE_SECTION_HEADER prev_sect; 

	ULONG new_hdrs_size; 

	ASSERT( NULL != _data ); 
	ASSERT( NULL != size ); 
	
	_size = *size; 
	data = *_data; 

	if( _size < sizeof( IMAGE_DOS_HEADER ) )
	{
		return -1; 
	}

	dos_hdr = ( PIMAGE_DOS_HEADER )data; 
	if( dos_hdr->e_magic != IMAGE_DOS_SIGNATURE )
	{
		return -1; 
	}

	if( dos_hdr->e_lfanew < sizeof( IMAGE_DOS_HEADER ) )
	{
		return -1; 
	}

	if( _size < dos_hdr->e_lfanew + sizeof( IMAGE_NT_HEADERS ) )
	{
		return -1; 
	}

	nt_hdrs = ( PIMAGE_NT_HEADERS )( data + dos_hdr->e_lfanew ); 
	if( nt_hdrs->Signature != IMAGE_NT_SIGNATURE )
	{
		return -1; 
	}
	
	if( nt_hdrs->FileHeader.SizeOfOptionalHeader < sizeof( IMAGE_OPTIONAL_HEADER ) )
	{
		return -1; 
	}

	if( nt_hdrs->OptionalHeader.SizeOfImage < _size )
	{
		return -1; 
	}

	sect_hdrs = ( PIMAGE_SECTION_HEADER )( data + 
		dos_hdr->e_lfanew + 
		sizeof( nt_hdrs->Signature ) + 
		sizeof( nt_hdrs->FileHeader ) + 
		nt_hdrs->FileHeader.SizeOfOptionalHeader ); 

	sect_hdrs_end = dos_hdr->e_lfanew + 
		sizeof( nt_hdrs->Signature ) + 
		sizeof( nt_hdrs->FileHeader ) + 
		nt_hdrs->FileHeader.SizeOfOptionalHeader + 
		nt_hdrs->FileHeader.NumberOfSections * 
		sizeof( IMAGE_SECTION_HEADER ); 

	if( nt_hdrs->OptionalHeader.SizeOfHeaders < sect_hdrs_end || 
		nt_hdrs->OptionalHeader.SizeOfImage < nt_hdrs->OptionalHeader.SizeOfHeaders )
	{
		return -1; 
	}

	if( ( nt_hdrs->OptionalHeader.SizeOfHeaders % nt_hdrs->OptionalHeader.SectionAlignment ) != 0 )
	{
		return -1; 
	}

	if( flags == OVERWRITE_SECTION_HEADER_TAIL_FILL_DATA )
	{
		if( ( nt_hdrs->OptionalHeader.SizeOfHeaders - sect_hdrs_end ) < sizeof( IMAGE_SECTION_HEADER ) )
		{
			return -1; 
		}

		new_hdrs_size = align( sect_hdrs_end + sizeof( IMAGE_SECTION_HEADER ), nt_hdrs->OptionalHeader.SectionAlignment ); 
		if( new_hdrs_size > nt_hdrs->OptionalHeader.SizeOfHeaders )
		{
			return -1; 
		}

		goto _set_new_sect; 
	}
	else if( flags == REMOVE_DOS_FILL_DATA )
	{
		if( dos_hdr->e_lfanew - sizeof( IMAGE_DOS_HEADER ) < sizeof( IMAGE_SECTION_HEADER ) )
		{
			return -1; 
		}

		memmove( data + dos_hdr->e_lfanew - sizeof( IMAGE_SECTION_HEADER ), 
			data + dos_hdr->e_lfanew, 
			sect_hdrs_end - dos_hdr->e_lfanew ); 

		dos_hdr->e_lfanew -= sizeof( IMAGE_SECTION_HEADER ); 

		nt_hdrs = ( PIMAGE_NT_HEADERS )( data + dos_hdr->e_lfanew ); 

		sect_hdrs = ( PIMAGE_SECTION_HEADER )( data + 
			dos_hdr->e_lfanew + 
			sizeof( nt_hdrs->Signature ) + 
			sizeof( nt_hdrs->FileHeader ) + 
			nt_hdrs->FileHeader.SizeOfOptionalHeader ); 

		//prev_sect = sect_hdrs[ nt_hdrs->FileHeader.NumberOfSections - 1 ]; 
		//new_sect = sect_hdrs[ nt_hdrs->FileHeader.NumberOfSections ]; 

		//sect_hdrs_end = dos_hdr->e_lfanew + 
		//	sizeof( nt_hdrs->Signature ) + 
		//	sizeof( nt_hdrs->FileHeader ) + 
		//	nt_hdrs->FileHeader.SizeOfOptionalHeader + 
		//	nt_hdrs->FileHeader.NumberOfSections * 
		//	sizeof( IMAGE_SECTION_HEADER ); 
	}
	else if( flags == APPEND_NEW_SECTION_SPACE )
	{
		PBYTE new_data; 
		ULONG new_img_size; 
		ULONG last_sect_vaddr; 
		ULONG last_sect_size; 
		INT32 i; 
		
		last_sect_vaddr = 0; 
		last_sect_size = 0; 

		for( i = 0; i < nt_hdrs->FileHeader.NumberOfSections; i ++ )
		{
			ASSERT( ( sect_hdrs[ i ].VirtualAddress % nt_hdrs->OptionalHeader.SectionAlignment ) == 0 ); 

			if( nt_hdrs->OptionalHeader.SizeOfHeaders < sect_hdrs[ i ].VirtualAddress )
			{
				return -1; 
			}

			if( sect_hdrs[ i ].VirtualAddress > last_sect_vaddr )
			{
				last_sect_vaddr = sect_hdrs[ i ].VirtualAddress; 
				last_sect_size = sect_hdrs[ i ].Misc.VirtualSize; 
			}
		}

		if( align( nt_hdrs->OptionalHeader.SizeOfImage, nt_hdrs->OptionalHeader.SectionAlignment ) < last_sect_vaddr + last_sect_size )
		{
			return -1; 
		}

		new_hdrs_size = align( nt_hdrs->OptionalHeader.SizeOfHeaders + sizeof( IMAGE_SECTION_HEADER ), nt_hdrs->OptionalHeader.SectionAlignment ); 
		new_img_size = nt_hdrs->OptionalHeader.SizeOfImage + ( new_hdrs_size - nt_hdrs->OptionalHeader.SizeOfHeaders ); 
		new_data = ( PBYTE )malloc( new_img_size ); 
		
		if( new_data == NULL )
		{
			return -1; 
		}

		memcpy( new_data, data, sect_hdrs_end ); 
		memcpy( new_data + new_hdrs_size, data + nt_hdrs->OptionalHeader.SizeOfHeaders, _size - nt_hdrs->OptionalHeader.SizeOfHeaders ); 

		free( data ); 
		dos_hdr = ( PIMAGE_DOS_HEADER )new_data; 
		nt_hdrs = ( PIMAGE_NT_HEADERS )( new_data + dos_hdr->e_lfanew ); 

		sect_hdrs = ( PIMAGE_SECTION_HEADER )( new_data + 
			dos_hdr->e_lfanew + 
			sizeof( nt_hdrs->Signature ) + 
			sizeof( nt_hdrs->FileHeader ) + 
			nt_hdrs->FileHeader.SizeOfOptionalHeader ); 

		//prev_sect = sect_hdrs[ nt_hdrs->FileHeader.NumberOfSections - 1 ]; 
		//new_sect = sect_hdrs[ nt_hdrs->FileHeader.NumberOfSections ]; 
	}

_set_new_sect:
	new_sect = &sect_hdrs[ nt_hdrs->FileHeader.NumberOfSections ]; 
	prev_sect = &sect_hdrs[ nt_hdrs->FileHeader.NumberOfSections - 1 ]; 

	memset( new_sect, 0, sizeof( IMAGE_SECTION_HEADER ) ); 

	new_sect->Characteristics = 0xE0000020; 
	new_sect->PointerToRawData = prev_sect->PointerToRawData + 
		prev_sect->SizeOfRawData; 
	new_sect->PointerToRawData = align( new_sect->PointerToRawData, nt_hdrs->OptionalHeader.FileAlignment ); 
	new_sect->SizeOfRawData = align( sect_size, nt_hdrs->OptionalHeader.FileAlignment ); 
	new_sect->VirtualAddress = prev_sect->VirtualAddress + prev_sect->Misc.VirtualSize; 
	new_sect->VirtualAddress = align( new_sect->VirtualAddress, nt_hdrs->OptionalHeader.SectionAlignment ); 
	new_sect->Misc.VirtualSize = align( sect_size, nt_hdrs->OptionalHeader.SectionAlignment ); 

	nt_hdrs->FileHeader.NumberOfSections += 1; 

	return 0; 
} 

INT32 pack_data(PCHAR data, ULONG size)
{
	INT32 ret; 
	PCHAR data_copy = NULL;
	UINT pack_work_space_size = NULL;	

	try
	{
		if( data == NULL || 
			size == 0 || 
			IsBadReadPtr( data, size ) )
		{
			return FALSE; 
		}

		//	初始化
		SAFE_RELEASE_MEM( pack_work_space ); 

		SAFE_RELEASE_MEM( packed_data ); 
		
		pack_work_space_size = 0; 
		packed_size = 0; 

		// 计算工作空间大小
		pack_work_space_size = aP_workmem_size( size );
		
		// 申请工作空间
		pack_work_space = ( CHAR* )malloc( pack_work_space_size ); 

		if( pack_work_space == NULL )
		{
			ret = FALSE; 
			goto _return; 
		}

		// 申请保存压缩数据的空间
		packed_data = ( CHAR* )malloc( size * 2 );
		if (packed_data == NULL)
		{
			ret = FALSE; 
			goto _return; 
		}

		// 申请空间
		data_copy = ( PCHAR )malloc( size );
		if( data_copy == NULL )
		{
			ret = FALSE; 
			goto _return; 
		}

		// 复制原始数据到新空间
		memcpy( data_copy, data, size ); 

		// 对原始数据进行压缩
		packed_size = aP_pack( ( PBYTE )data_copy, 
			( PBYTE )packed_data, 
			size, 
			( PBYTE )pack_work_space, 
			NULL, 
			0 );
		
		// 释放新空间
		free( data_copy ); 

		data_copy = NULL;
		
		if( packed_size == 0)
		{
			ret = FALSE; 
			goto _return; 
		}
	}
	catch (...)
	{
		ret = FALSE; 
		goto _return; 
	}

	return TRUE; 

_return:
	SAFE_RELEASE_MEM( pack_work_space ); 
	SAFE_RELEASE_MEM( packed_data ); 
	SAFE_RELEASE_MEM( data_copy ); 

	return ret; 

}

INT32 pack_pe_file( LPCSTR file_name )
{
	//将 绑定输入 清零
	INT32 ret = FALSE; 
	PIMAGE_DATA_DIRECTORY bound_import_dir; 
	PIMAGE_BOUND_IMPORT_DESCRIPTOR	bound_import; 
	PIMAGE_DATA_DIRECTORY debug_dir; 
	PIMAGE_DATA_DIRECTORY iat_dir;
	DWORD remain_header_size; 
	PCHAR sect_data;
	DWORD sect_data_size;
	DWORD correct_sect_data_size;
	DWORD all_packed_size = 0;
	DWORD writed;
	DWORD offset; 
	INT32 i; 

	packed_file = CreateFile( file_name,
		GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_READ | FILE_SHARE_WRITE, 
		NULL, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL ); 

	if( packed_file == INVALID_HANDLE_VALUE )
	{
		DBGPRINT( ( "create file failed\n" ) );
		return FALSE;
	}
	
	bound_import_dir = &img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT ]; 
	if ( bound_import_dir->VirtualAddress != NULL && 
		bound_import_dir->Size > 0 )
	{
		bound_import = ( PIMAGE_BOUND_IMPORT_DESCRIPTOR )rva2va( bound_import_dir->VirtualAddress );
		memset( bound_import,0, bound_import_dir->Size );
		
		bound_import_dir->VirtualAddress = 0; 
		bound_import_dir->Size = 0;	
	}

	debug_dir = &img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ]; 
	if( debug_dir->VirtualAddress != 0 && 
		debug_dir->Size > 0 )
	{
		memset( ( PCHAR )rva2va( debug_dir->VirtualAddress ), 0, debug_dir->Size ); 

		memset( debug_dir, 0, sizeof( IMAGE_DATA_DIRECTORY ) ); 
	}
	
	//清除IAT信息
	iat_dir = &img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IAT ];
	
	if( iat_dir->VirtualAddress != NULL )
	{
		memset( ( PCHAR ) rva2va( iat_dir->VirtualAddress ), 0, iat_dir->Size );
		iat_dir->VirtualAddress = 0;
		iat_dir->Size = 0;
	}

	//保留3个节表
	remain_header_size = ( DWORD )&img_section_hdrs[ REMAIN_SECTION_NUM ] - ( DWORD )img_base;
	//修正第一个节的文件偏移	
	img_nt_hdr->OptionalHeader.SizeOfHeaders = align( remain_header_size, img_file_align );
    
	img_nt_hdr->FileHeader.NumberOfSections = REMAIN_SECTION_NUM; 

	DBGPRINT( ( "now remain pe header size:%X\n", remain_header_size ) );

	//写入PE头部
	//if( !WriteFile( packed_file, img_base, img_nt_hdr->OptionalHeader.SizeOfHeaders, &writed, NULL ) )
	//{
	//	DBGPRINT( ( "write pe head failed\n" ) );
	//	ret = FALSE; 
	//	goto _return; 
	//}

	SetFilePointer( packed_file,
		img_nt_hdr->OptionalHeader.SizeOfHeaders, 
		NULL, 
		FILE_BEGIN ); 

	memset( pack_infos, 0, sizeof( PACKET_INFO ) * 10 );
	
	img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].PointerToRawData = align( remain_header_size, img_file_align ); 
	img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].VirtualAddress = align( remain_header_size, img_section_align );
	img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].Misc.VirtualSize = align( img_load_size, img_section_align );
	img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].SizeOfRawData = align( 4, img_file_align );
	img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].Characteristics = PACK_FILE_SECTION_FLAGS; 
	strcpy( ( CHAR* )img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].Name, ".txt" ); 

	shell_infos[ UNPACK_SPACE_RVA ] = img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].VirtualAddress; 

	{
		PVOID zero; 
		zero = malloc( img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].SizeOfRawData );
		if( zero == NULL )
		{
			goto _return; 
		}

		memset( zero, 0, img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].SizeOfRawData );

		if( ! WriteFile( packed_file, zero, img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].SizeOfRawData, &writed, NULL ) )
		{
			DBGPRINT( ( "write zero buff failed\n" ) );
			goto _return; 
		}

		free( zero ); 
	}

	for( i = 0; i < img_sect_num; i++ )
	{
		sect_data = ( PCHAR )rva2va( img_section_hdrs[ i ].VirtualAddress );
		
		DBGPRINT( ( "write pack section %d:%X\n", i, img_section_hdrs[ i ].VirtualAddress ) );
		
		sect_data_size = img_section_hdrs[ i ].Misc.VirtualSize; 

		if( i == PACK_DATA_SECTION_INDEX )
		{
			HANDLE data_check_file; 
			DBGPRINT( ( "write packed section %s\n",( CHAR* )img_section_hdrs[ i ].Name ) );
#define DATA_CHECK_FILE_NAME "look0.dat"
			data_check_file = CreateFile( DATA_CHECK_FILE_NAME, 
				GENERIC_WRITE, 
				0, 
				NULL, 
				CREATE_ALWAYS, 
				FILE_ATTRIBUTE_NORMAL, 
				NULL );

			if( data_check_file != INVALID_HANDLE_VALUE )
			{
				WriteFile( data_check_file, sect_data, sect_data_size, &writed, NULL );
				CloseHandle( data_check_file );
			}
			else
			{
				DBGPRINT( ( "create data check file failed\n" ) ); 
			}
		}

		//去除节尾部的零数据
		correct_sect_data_size = valid_data_size( sect_data, sect_data_size ); 
		pack_infos[ i ].unpack_size = correct_sect_data_size;
		
		//压缩此节
		if( !pack_data( sect_data, correct_sect_data_size ) )
		{
			DBGPRINT( ( "pack section failed\n" ) );
			ret = FALSE; 
			goto _return; 
		}

		DBGPRINT( ( "%s pack ok,size:%d orginal size is %d \n", img_section_hdrs[i].Name, packed_size, sect_data_size ) );
		
		//写入压缩后数据
		if( !WriteFile( packed_file, packed_data, packed_size, &writed, NULL ) )
		{
			DBGPRINT( ( "write packed section %s failed\n", img_section_hdrs[ i ].Name ) );
			
			ret = FALSE; 
			goto _return; 
		}

		all_packed_size += packed_size;
		pack_infos[ i ].packed_size = packed_size;
		pack_infos[ i ].vaddr = img_section_hdrs[i].VirtualAddress;
		pack_infos[ i ].vsize = img_section_hdrs[i].Misc.VirtualSize;
	}

	img_section_hdrs[ PACK_DATA_SECTION_INDEX ].PointerToRawData = align( remain_header_size + img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].PointerToRawData, img_file_align ); 
	img_section_hdrs[ PACK_DATA_SECTION_INDEX ].VirtualAddress = align( remain_header_size + img_section_hdrs[ UNPACK_SPACE_SECTION_INDEX ].PointerToRawData, img_section_align );
	img_section_hdrs[ PACK_DATA_SECTION_INDEX ].Misc.VirtualSize = align( all_packed_size, img_section_align );
	img_section_hdrs[ PACK_DATA_SECTION_INDEX ].SizeOfRawData = align( all_packed_size, img_file_align );
	img_section_hdrs[ PACK_DATA_SECTION_INDEX ].Characteristics = PACK_FILE_SECTION_FLAGS; 

	strcpy( ( CHAR* )img_section_hdrs[ PACK_DATA_SECTION_INDEX ].Name, ".pdata" );

	shell_infos[ PACKET_DATA_RVA ] = img_section_hdrs[ PACK_DATA_SECTION_INDEX ].VirtualAddress; 

	if( img_section_hdrs[ PACK_DATA_SECTION_INDEX ].SizeOfRawData > all_packed_size )
	{
		PVOID zero; 
		zero = malloc( img_section_hdrs[ PACK_DATA_SECTION_INDEX ].SizeOfRawData - all_packed_size );
		if( zero == NULL )
		{
			goto _return; 
		}

		memset( zero, 0, img_section_hdrs[ PACK_DATA_SECTION_INDEX ].SizeOfRawData - all_packed_size );
		
		if( ! WriteFile( packed_file, zero, img_section_hdrs[PACK_DATA_SECTION_INDEX].SizeOfRawData - all_packed_size, &writed, NULL ) )
		{
			DBGPRINT( ( "write zero buff failed\n" ) );
			goto _return; 
		}

		free( zero ); 
	}

	ret = TRUE; 

_return:
	//if( packed_file != INVALID_HANDLE_VALUE )
	//{
	//	CloseHandle( packed_file ); 
	//}

	return ret;
}

