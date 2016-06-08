#include "common.h"
#include "common_analyze.h"
#include "pe_file_analyzer.h"
#include "lib_file_analyzer.h"
#include "file_analyzer.h"

typedef int ( callback check_this_file_type )( byte *data, dword data_len );
void* g_check_file_funcs[] =
{
	( void* )check_pe_file_type,
	( void* )check_lib_file_type,
	( void* )check_coff_file_type
};

file_analyzer *global_analyzer = NULL;
void set_file_analyzer( file_analyzer *analyzer )
{
	global_analyzer = analyzer;
}

int init_analyzing( CHAR *filename, file_analyzer *analyzer )
{
	int ret;

	byte *data;
	dword data_len;

	ASSERT( NULL != analyzer );
	ret = read_all_file_data( filename, &data, &data_len );
	analyzer->all_file_data = data;
	analyzer->file_data_len = data_len;

	if( 0 != ret )
	{
		if( NULL != analyzer->error_handler )
		{
			error_infos info;
			info.err_code = ERR_FILE_NOT_EXIST;
			info.desc = "This file is not existing";

			analyzer->error_handler( &info );
		}
		return -1;
	}

	analyzer->file_type = check_file_type( data, data_len );
	if( PE_FILE_TYPE == analyzer->file_type )
	{
		ret = analyze_pe_file_struct( data, data_len, analyzer );
	}
	else if( LIB_FILE_TYPE == analyzer->file_type )
	{
		ret = analyze_lib_file_struct( data, data_len, analyzer  );
	}
	else if( COFF_FILE_TYPE == analyzer->file_type )
	{
		ret = analyze_coff_file_struct( data, data_len, 0, analyzer );
	}

	return ret;
}

int32 check_file_type( byte *data, dword data_len )
{
	int ret;
	int i;
	ASSERT( NULL != data );
	ASSERT( 0 <= data_len );

	for( i = 0; i < sizeof( g_check_file_funcs ) / sizeof( void* ); i ++ )
	{
		check_this_file_type *check_proc;
		check_proc = ( check_this_file_type* )g_check_file_funcs[ i ];
		ret = check_proc( data, data_len );
		if( 0 <= ret )
		{
			return ret;
		}
	}

	return -1;
}

int32 callback compare_struct_info( void *element1, void *element2 )
{
	struct_infos *info1;
	struct_infos *info2;

	ASSERT( NULL != element1 );
	ASSERT( NULL != element2 );

	info1 = ( struct_infos* )element1;
	info2 = ( struct_infos* )element2;

	if( info1->struct_id == info2->struct_id && info1->struct_index == info2->struct_index )
	{
		return 0;
	}

	return -1;
}

struct_infos *find_struct_info_by_id( dword type, dword index )
{
	struct_infos info;
	info.struct_id = type;
	info.struct_index = index;

	return find_struct_info( &info );
}

struct_infos *find_struct_info( struct_infos *info )
{
	return ( struct_infos* )find_record_info( ( void* )info, compare_struct_info );
}

