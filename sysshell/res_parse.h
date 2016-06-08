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

//typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
//	union {
//		struct {
//			DWORD NameOffset:31;
//			DWORD NameIsString:1;
//		};
//		DWORD   Name;
//		WORD    Id;
//	};
//	union {
//		DWORD   OffsetToData;
//		struct {
//			DWORD   OffsetToDirectory:31;
//			DWORD   DataIsDirectory:1;
//		};
//	};
//} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

DWORD read_type_res( DWORD type, PBYTE output_buff, DWORD begin_rva )
{
	PIMAGE_DATA_DIRECTORY res_data_dir;
	PIMAGE_RESOURCE_DIRECTORY res_dir;
	
	PIMAGE_RESOURCE_DIRECTORY name_res;
	PIMAGE_RESOURCE_DIRECTORY lang_res_dir;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY type_entry;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY name_entry;
	ULONG name_res_count; 
	
	PIMAGE_RESOURCE_DIRECTORY_ENTRY lang_res_entry;
	ULONG lang_res_count; 

	PIMAGE_RESOURCE_DATA_ENTRY data_entry;

	ULONG type_count; 
	INT32 i; 
	INT32 j; 
	INT32 k; 

	PIMAGE_RESOURCE_DIR_STRING_U res_name;

	DWORD outputed_size=0;
//	DWORD shell0Size;

	res_data_dir = ( PIMAGE_DATA_DIRECTORY )&img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ];
	if( res_data_dir->VirtualAddress == 0 )
	{
		DBGPRINT( ( "this file have not resource data\n" ) );
		return 0;
	}

	res_dir = ( PIMAGE_RESOURCE_DIRECTORY )rva2va( res_data_dir->VirtualAddress );
	type_count = res_dir->NumberOfIdEntries + res_dir->NumberOfNamedEntries; 
	
	type_entry = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )res_dir + sizeof( IMAGE_RESOURCE_DIRECTORY ) );

	//	shell0Size= (DWORD) (&ShellEnd0) - (DWORD)(&ShellStart0);

	for( i = 0; i < type_count; i++ )
	{
		if( type_entry[ i ].NameIsString != 0 || type_entry[i].DataIsDirectory != 1 )
		{
			continue; 
		}

		if( type_entry[ i ].Id != type )
		{
			continue; 
		}

		name_res = ( PIMAGE_RESOURCE_DIRECTORY )( ( DWORD )res_dir + ( DWORD )type_entry[ i ].OffsetToDirectory );
		
		name_res_count = name_res->NumberOfIdEntries + name_res->NumberOfNamedEntries;
		
		name_entry = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )name_res + sizeof( IMAGE_RESOURCE_DIRECTORY ) );

		for( j = 0; j < name_res_count; j++ )
		{
			DBGPRINT( ( "is string %d, is dir %d\n", name_entry[j].NameIsString, 
				name_entry[ j ].DataIsDirectory ) );

			if( name_entry[ j ].DataIsDirectory != 1 )
			{
				continue; 
			}

			res_name = ( PIMAGE_RESOURCE_DIR_STRING_U )( ( DWORD )res_dir + name_entry[ j ].NameOffset ); 
			DBGPRINT( ( "res name %s\n",res_name->NameString ) );

			lang_res_dir = ( PIMAGE_RESOURCE_DIRECTORY )( ( DWORD )res_dir + name_entry[ j ].OffsetToDirectory );
			lang_res_count = lang_res_dir->NumberOfIdEntries + lang_res_dir->NumberOfNamedEntries; 
			
			lang_res_entry = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )lang_res_dir + sizeof( IMAGE_RESOURCE_DIRECTORY ) ); 
			for( k = 0; k < lang_res_count; k++ )
			{
				if( lang_res_entry[k].NameIsString != 0 || lang_res_entry[k].DataIsDirectory != 0 )
				{
					continue; 
				}
				
				DBGPRINT( ( "lang res name is string %d, data is dir %d\n", lang_res_entry[ k ].NameIsString, 
					lang_res_entry[ k ].DataIsDirectory ) );

				data_entry =( PIMAGE_RESOURCE_DATA_ENTRY )( ( DWORD )res_dir + lang_res_entry[ k ].OffsetToData );

				if( output_buff != NULL )
				{
					memcpy( &output_buff[ outputed_size ], 
						( PBYTE )rva2va( data_entry->OffsetToData ), 
						data_entry->Size ); 

					memset( ( PBYTE )rva2va( data_entry->OffsetToData ), 0, data_entry->Size ); 

					data_entry->OffsetToData = begin_rva;
					begin_rva += data_entry->Size;
				}

				outputed_size += data_entry->Size;

				DBGPRINT( ( "rva:%X,size:%X\n", data_entry->OffsetToData, data_entry->Size ) );
			}
		}
	}
	return outputed_size;
}

INT32 reloc_type_res( DWORD type, DWORD offset )
{
	PIMAGE_DATA_DIRECTORY res_data_dir;
	PIMAGE_RESOURCE_DIRECTORY res_dir;
	PIMAGE_RESOURCE_DIRECTORY name_res;
	PIMAGE_RESOURCE_DIRECTORY lang_res_dir;

	PIMAGE_RESOURCE_DIRECTORY_ENTRY type_entry; 
	ULONG type_count; 

	PIMAGE_RESOURCE_DIRECTORY_ENTRY name_entry;
	ULONG name_res_count; 
	
	PIMAGE_RESOURCE_DIRECTORY_ENTRY lang_res_entry;
	ULONG lang_res_count; 

	PIMAGE_RESOURCE_DATA_ENTRY data_entry;

	PIMAGE_RESOURCE_DIR_STRING_U res_name;

	INT32 i; 
	INT32 j; 
	INT32 k; 

	//DWORD shell0Size;

	res_data_dir = ( PIMAGE_DATA_DIRECTORY )&img_nt_hdr->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_RESOURCE ];
	
	if( res_data_dir->VirtualAddress == 0 )
	{
		DBGPRINT( ( "this file have not resource data\n" ) );
		return 0;
	}

	res_dir = ( PIMAGE_RESOURCE_DIRECTORY )rva2va( res_data_dir->VirtualAddress );
	type_count = res_dir->NumberOfIdEntries + res_dir->NumberOfNamedEntries; 
	type_entry = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )res_dir + sizeof( IMAGE_RESOURCE_DIRECTORY ) );

	//	shell0Size= (DWORD) (&ShellEnd0) - (DWORD)(&ShellStart0) ;
	for( i = 0; i < type_count; i++ )
	{
		if( type_entry[ i ].NameIsString != 0 || 
			type_entry[i].DataIsDirectory != 1 )
		{
			continue; 
		}

		if( type_entry[ i ].Id != type )
		{
			continue; 
		}

		name_res = ( PIMAGE_RESOURCE_DIRECTORY )( ( DWORD )res_dir + ( DWORD )type_entry[ i ].OffsetToDirectory ); 
		name_res_count = name_res->NumberOfIdEntries + name_res->NumberOfNamedEntries; 
		name_entry = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )name_res + sizeof( IMAGE_RESOURCE_DIRECTORY ) );

		for( j = 0; j < name_res_count; j++ )
		{
			DBGPRINT( ("name is string %d, data is dir %d\n",name_entry[j].NameIsString,name_entry[j].DataIsDirectory ) );

			if( name_entry[ j ].DataIsDirectory !=1 )
			{
				continue; 
			}

			res_name = ( PIMAGE_RESOURCE_DIR_STRING_U )( ( DWORD )res_dir + name_entry[ j ].NameOffset );
			DBGPRINT( ( "name string is %s\n", res_name->NameString ) );

			lang_res_dir = ( PIMAGE_RESOURCE_DIRECTORY )( ( DWORD )res_dir + name_entry[j].OffsetToDirectory ); 
			lang_res_count = lang_res_dir->NumberOfIdEntries + lang_res_dir->NumberOfNamedEntries; 
			lang_res_entry =( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )lang_res_dir + sizeof( IMAGE_RESOURCE_DIRECTORY ) ); 

			for( k = 0; k < lang_res_count; k++ )
			{
				if( lang_res_entry[k].NameIsString != 0 || 
					lang_res_entry[k].DataIsDirectory != 0 )
				{
					continue; 
				}

				DBGPRINT( ( "name is string %d, data is dir %d\n", 
					lang_res_entry[k].NameIsString, 
					lang_res_entry[k].DataIsDirectory ) ); 

				data_entry = ( PIMAGE_RESOURCE_DATA_ENTRY )( ( DWORD )res_dir + lang_res_entry[ k ].OffsetToData ); 

				data_entry->OffsetToData += offset;

			}
		}
	}

	return 0;
}


//保存资源目录
INT32 get_img_res_dir()
{
	ULONG res_begin_addr = NULL;
	
	PIMAGE_DATA_DIRECTORY res_data_dir = NULL;
	PIMAGE_RESOURCE_DIRECTORY res_dir = NULL;
	
	PIMAGE_RESOURCE_DIRECTORY type_res_dir = NULL;
	PIMAGE_RESOURCE_DIRECTORY name_res_dir = NULL;
	PIMAGE_RESOURCE_DIRECTORY lang_res_dir = NULL;
	
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	type_entry = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	name_res_entry = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY	lang_res_entry = NULL;
	
	PIMAGE_RESOURCE_DATA_ENTRY res_data = NULL;
	
	ULONG type_res_count;
	ULONG name_res_count;
	ULONG lang_res_count;

	ULONG i = 0;
	ULONG j = 0;
	ULONG k = 0;

	try
	{
		res_begin_addr = img_nt_hdr->OptionalHeader.SizeOfImage; //现放置一个最大值（这里取映像尺寸），然后根据比较逐渐减小
		
		res_data_dir = &img_nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		if (res_data_dir->VirtualAddress == NULL)
		{
			return FALSE;
		}
		
		res_dir = ( PIMAGE_RESOURCE_DIRECTORY )rva2va( res_data_dir->VirtualAddress ); //资源起点地址
		
		type_res_dir = res_dir;
		type_res_count = type_res_dir->NumberOfIdEntries + type_res_dir->NumberOfNamedEntries; //该类型中有几类资源
		type_entry  = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )type_res_dir + sizeof( IMAGE_RESOURCE_DIRECTORY ) );
		
		for( i = 0; i < type_res_count; i++, type_entry++ )
		{
			
			//该类型目录地址
			name_res_dir = ( PIMAGE_RESOURCE_DIRECTORY )( ( DWORD )res_dir + ( DWORD )type_entry->OffsetToDirectory );
			//该类型中有几个项目
			name_res_count = name_res_dir->NumberOfIdEntries + name_res_dir->NumberOfNamedEntries; 
			name_res_entry = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )name_res_dir + sizeof( IMAGE_RESOURCE_DIRECTORY ) );
			
			for ( j = 0; j < name_res_count; j++, name_res_entry++ )
			{
				//该项目目录地址
				lang_res_dir = ( PIMAGE_RESOURCE_DIRECTORY )( ( DWORD )res_dir + ( DWORD )name_res_entry->OffsetToDirectory ); 
				lang_res_count = lang_res_dir->NumberOfIdEntries + lang_res_dir->NumberOfNamedEntries; 
				lang_res_entry = ( PIMAGE_RESOURCE_DIRECTORY_ENTRY )( ( DWORD )lang_res_dir + sizeof( IMAGE_RESOURCE_DIRECTORY ) ); 
				
				for( k = 0; k < lang_res_count; k ++, lang_res_entry++ )
				{
					res_data = ( PIMAGE_RESOURCE_DATA_ENTRY )( ( DWORD )res_dir + ( DWORD )lang_res_entry->OffsetToData ); 
					
					if(( res_data->OffsetToData < res_begin_addr ) && ( res_data->OffsetToData > res_data_dir->VirtualAddress ) ) 
					{
						res_begin_addr = res_data->OffsetToData;
					}
				}				
			}
		}
		
		
	}
	catch (...)
	{
		return FALSE;
	}
	
	img_res_dir_size = res_begin_addr - res_data_dir->VirtualAddress; 
	img_res_dir = malloc( img_res_dir_size ); 

	memcpy( img_res_dir, rva2va( res_data_dir->VirtualAddress ), img_res_dir_size ); 
	
	return TRUE; 
}
