#include "common.h"
#include "common_analyze.h"
#include "coff_file_analyzer.h"
#include "lib_file_analyzer.h"
#include "lib_struct_analyzer.h"

int32 coff_optional32_hdr_analyze( const coff_opt_hdr28 *opt_hdr )
{
	coff_opt_hdr28 *opt_hdr28;

	opt_hdr28 = opt_hdr;

	opt_hdr28->magic == 0x010b; //exe
	opt_hdr28->magic == 0x0107; //rom 
	opt_hdr28->entry;
	opt_hdr28->version;
	opt_hdr28->text_base;

	return 0;
}

int32 coff_file_hdr_analyze( const coff_file_hdr *file_hdr )
{

	ASSERT( NULL != file_hdr );
	file_hdr->time;
	file_hdr->sect_num;
	file_hdr->syms_num;
	file_hdr->syms_offset;

	return 0;
}

int32 coff_sect_hdr_analyze( const coff_sect_hdr *sect_hdr )
{

	sect_hdr->flags;
	sect_hdr->ln_table_offset;

	return 0;
}