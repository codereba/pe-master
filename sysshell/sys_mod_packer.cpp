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

#include "common.h"
#include "aplib\aplib.h"
#pragma comment(lib, "aplib\\aplib.lib") 

#pragma comment( linker, "/MERGE:.gdata=.gcode" )
#pragma comment( linker, "/section:.gcode,rw"  )

/*
generate cod file cl.exe command: 
cl /Od /I"E:\WinDDK\7600.16385.1\inc\ddk" /I"E:\WinDDK\7600.16385.1\inc\api" /I"E:\WinDDK\7600.16385.1\inc\crt" /D"_X86_" /D"DBG" /D"_MBCS" /Gm /Fx /FAcs /Fa"./" /Fo"./" /Fd"./" /W3 /nologo /Wp64 /ZI /Tc   cancel.c 
*/

#include "ddk.h"

#include "sys_mod_packer.h"
#include "import_code.h"
#include "section_build.h"
#include "res_parse.h"
#include "img_chk_sum.h"
#include "shell_code.h"
#include "shell_builder.h"
#include "file_pack.h" 
#include "pe_file_map.h"

class test_class
{
public:
	test_class() { test[ 0 ] = 1; } 
	~test_class() { test[ 0 ] = 0; }

	CHAR test[ 1024 ]; 
}; 

ULONG test_g_var = 0;
PVOID _stdcall relocate_addr_in_other_image(PVOID pVar); 

//PVOID
//NTAPI
//RtlEncodePointer(IN PVOID Pointer)
//{
//	ULONG Cookie;
//	NTSTATUS Status;
//
//	Status = ZwQueryInformationProcess(NtCurrentProcess(),
//		ProcessCookie,
//		&Cookie,
//		sizeof(Cookie),
//		NULL);
//	if(!NT_SUCCESS(Status))
//	{
//		DPRINT1("Failed to receive the process cookie! Status: 0x%lx\n", Status);
//		return Pointer;
//	}
//
//	return (PVOID)((ULONG_PTR)Pointer ^ Cookie);
//}
//
///*
//* @implemented
//*/
//PVOID
//NTAPI
//RtlDecodePointer(IN PVOID Pointer)
//{
//	return RtlEncodePointer(Pointer);
//}


//#include <winbase.h>
//extern "C"
//{
//PVOID WINAPI RtlEncodePointer(
//  __in  PVOID Ptr
//);
//
//PVOID WINAPI RtlDecodePointer(
//    PVOID Ptr
//);
//}

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

//#define MEMORY_REQUESTED 1024*1024 // request a megabyte
//
//BOOL
//LoggedSetLockPagesPrivilege ( HANDLE hProcess,
//                              BOOL bEnable);
//
//void _cdecl main()
//{
//  BOOL bResult;                   // generic Boolean value
//  ULONG_PTR NumberOfPages;        // number of pages to request
//  ULONG_PTR NumberOfPagesInitial; // initial number of pages requested
//  ULONG_PTR *aPFNs;               // page info; holds opaque data
//  PVOID lpMemReserved;            // AWE window
//  SYSTEM_INFO sSysInfo;           // useful system information
//  int PFNArraySize;               // memory to request for PFN array
//
//  GetSystemInfo(&sSysInfo);  // fill the system information structure
//
//  _tprintf(_T("This computer has page size %d.\n"), sSysInfo.dwPageSize);
//
//  // Calculate the number of pages of memory to request.
//
//  NumberOfPages = MEMORY_REQUESTED/sSysInfo.dwPageSize;
//  _tprintf (_T("Requesting %d pages of memory.\n"), NumberOfPages);
//
//  // Calculate the size of the user PFN array.
//
//  PFNArraySize = NumberOfPages * sizeof (ULONG_PTR);
//
//  _tprintf (_T("Requesting a PFN array of %d bytes.\n"), PFNArraySize);
//
//  aPFNs = (ULONG_PTR *) HeapAlloc(GetProcessHeap(), 0, PFNArraySize);
//
//  if (aPFNs == NULL) 
//  {
//    _tprintf (_T("Failed to allocate on heap.\n"));
//    return;
//  }
//
//  // Enable the privilege.
//
//  if( ! LoggedSetLockPagesPrivilege( GetCurrentProcess(), TRUE ) ) 
//  {
//    return;
//  }
//
//  // Allocate the physical memory.
//
//  NumberOfPagesInitial = NumberOfPages;
//  bResult = AllocateUserPhysicalPages( GetCurrentProcess(),
//                                       &NumberOfPages,
//                                       aPFNs );
//    
//  if( bResult != TRUE ) 
//  {
//    _tprintf(_T("Cannot allocate physical pages (%u)\n"), GetLastError() );
//    return;
//  }
//
//  if( NumberOfPagesInitial != NumberOfPages ) 
//  {
//    _tprintf(_T("Allocated only %p pages.\n"), NumberOfPages );
//    return;
//  }
//
//  // Reserve the virtual memory.
//    
//  lpMemReserved = VirtualAlloc( NULL,
//                                MEMORY_REQUESTED,
//                                MEM_RESERVE | MEM_PHYSICAL,
//                                PAGE_READWRITE );
//
//  if( lpMemReserved == NULL ) 
//  {
//    _tprintf(_T("Cannot reserve memory.\n"));
//    return;
//  }
//
//  // Map the physical memory into the window.
//    
//  bResult = MapUserPhysicalPages( lpMemReserved,
//                                  NumberOfPages,
//                                  aPFNs );
//
//  if( bResult != TRUE ) 
//  {
//    _tprintf(_T("MapUserPhysicalPages failed (%u)\n"), GetLastError() );
//    return;
//  }
//
//  // unmap
//    
//  bResult = MapUserPhysicalPages( lpMemReserved,
//                                  NumberOfPages,
//                                  NULL );
//
//  if( bResult != TRUE ) 
//  {
//    _tprintf(_T("MapUserPhysicalPages failed (%u)\n"), GetLastError() );
//    return;
//  }
//
//  // Free the physical pages.
//
//  bResult = FreeUserPhysicalPages( GetCurrentProcess(),
//                                   &NumberOfPages,
//                                   aPFNs );
//
//  if( bResult != TRUE ) 
//  {
//    _tprintf(_T("Cannot free physical pages, error %u.\n"), GetLastError());
//    return;
//  }
//
//  // Free virtual memory.
//
//  bResult = VirtualFree( lpMemReserved,
//                         0,
//                         MEM_RELEASE );
//
//  // Release the aPFNs array.
//
//  bResult = HeapFree(GetProcessHeap(), 0, aPFNs);
//
//  if( bResult != TRUE )
//  {
//      _tprintf(_T("Call to HeapFree has failed (%u)\n"), GetLastError() );
//  }
//
//}
//
///*****************************************************************
//   LoggedSetLockPagesPrivilege: a function to obtain or
//   release the privilege of locking physical pages.
//
//   Inputs:
//
//       HANDLE hProcess: Handle for the process for which the
//       privilege is needed
//
//       BOOL bEnable: Enable (TRUE) or disable?
//
//   Return value: TRUE indicates success, FALSE failure.
//
//*****************************************************************/
//BOOL
//LoggedSetLockPagesPrivilege ( HANDLE hProcess,
//                              BOOL bEnable)
//{
//  struct {
//    DWORD Count;
//    LUID_AND_ATTRIBUTES Privilege [1];
//  } Info;
//
//  HANDLE Token;
//  BOOL Result;
//
//  // Open the token.
//
//  Result = OpenProcessToken ( hProcess,
//                              TOKEN_ADJUST_PRIVILEGES,
//                              & Token);
//
//  if( Result != TRUE ) 
//  {
//    _tprintf( _T("Cannot open process token.\n") );
//    return FALSE;
//  }
//
//  // Enable or disable?
//
//  Info.Count = 1;
//  if( bEnable ) 
//  {
//    Info.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
//  } 
//  else 
//  {
//    Info.Privilege[0].Attributes = 0;
//  }
//
//  // Get the LUID.
//
//  Result = LookupPrivilegeValue ( NULL,
//                                  SE_LOCK_MEMORY_NAME,
//                                  &(Info.Privilege[0].Luid));
//
//  if( Result != TRUE ) 
//  {
//    _tprintf( _T("Cannot get privilege for %s.\n"), SE_LOCK_MEMORY_NAME );
//    return FALSE;
//  }
//
//  // Adjust the privilege.
//
//  Result = AdjustTokenPrivileges ( Token, FALSE,
//                                   (PTOKEN_PRIVILEGES) &Info,
//                                   0, NULL, NULL);
//
//  // Check the result.
//
//  if( Result != TRUE ) 
//  {
//    _tprintf (_T("Cannot adjust token privileges (%u)\n"), GetLastError() );
//    return FALSE;
//  } 
//  else 
//  {
//	  DWORD err_code; 
//    if( ( err_code = GetLastError() ) != ERROR_SUCCESS ) 
//    {
//      _tprintf (_T("Cannot enable the SE_LOCK_MEMORY_NAME privilege; "));
//      _tprintf (_T("please check the local policy.\n"));
//      return FALSE;
//    }
//  }
//
//  CloseHandle( Token );
//
//  return TRUE;
//}
//

CHAR *test; 
int main(int argc, char* argv[])
{
	//INT32 test = 300; 
	//FatalExit( 0 ); 

	//test_class *test = new test_class(); 

	//PVOID enc_ptr = EncodePointer( test ); 
	//test = ( test_class * )DecodePointer( enc_ptr ); 

	//INT32 test2 = test > 267 ? DBGPRINT( ( "test > 267\n" ) ) : test; 

	//CHAR *test = new CHAR[ 9023481293481 ]; 
	//test = 0; 

	WCHAR test[] = L"abc"; 

	//anti_debug3(); 

	//try
	//{
	//	*( 0 ) = 0; 
	//}
	//catch
	//{
	//	int i = 0; 
	//}

	test[0 ] = toupper( test[ 0 ] ); 
	INT32 ret; 
	LPCSTR file_name; 
	LPCSTR out_file_name; 
	DWORD _import_codes_size; 
	DWORD readed_size; 
	DWORD readed_res_size; 
	PBYTE res_cur; 
	DWORD entry_ptr; 
	//CHAR TEST[] = { 'T', 'E', 'S', 'T', 'T', 'E', 'S', 'T' }; 

	file_name = argv[ 1 ]; 
	out_file_name = argv[ 2 ]; 

	PVOID kern_mod; 

	//relocate_addr_in_other_image( &test_g_var ); 
	//kern_mod = get_kern_base(); 
	//kern_mod = ( PVOID )get_mod_base( NULL, L"msvcrt.dll" ); 
	
	//把文件load入内存

	ret = map_pe_file( file_name ); 

	if( FALSE == ret )
	{
		DBGPRINT( ( "map file failed\n" ) );
		return 0;

	}

	//entry_ptr = img_nt_hdr->OptionalHeader.AddressOfEntryPoint; 

	//__asm
	//{
	//	push eax; 
	//	mov eax, dword ptr [ img_base ]; 
	//	add eax, dword ptr [ entry_ptr ]; 
	//	push 0; 
	//	push 0; 
	//	call eax; 
	//	pop eax; 
	//};
	//DBGPRINT( ( "global address 0x%0.8x \n", &test_g_var ) ); 

	//relocate_addr_in_other_image( &test_g_var ); 

	//转储导出表
	_import_codes_size = 0;
	//计算要转储需要的内存大小
	if( !encode_import_table( NULL, &_import_codes_size ) )
	{
		DBGPRINT( ( "get need size failed\n" ) );
		return FALSE;
	}

	import_codes_size = _import_codes_size + 4; 
	DBGPRINT( ( "import_codes_size:%D\n",import_codes_size ) );

	//转储导入表
	import_codes = ( PBYTE )malloc( import_codes_size );
	if( NULL == import_codes )
	{
		DBGPRINT( ( "allocate import code buffer failed\n" ) ); 
		return FALSE; 
	}

	memset( import_codes, 0, import_codes_size );

	if( !encode_import_table( import_codes, NULL ) )
	{
		DBGPRINT( ("code improt data failed\n" ) );
		return FALSE;
	}  

	//清除导入表
	clear_import_tbl();
	
	//移动不可压缩资源
	no_pack_res_size = read_type_res( 0x3, NULL, 0 ) + 
		read_type_res( 0x0e, NULL, 0 ) + 
		read_type_res( 0x10, NULL, 0 ) + 
		read_type_res( 0x18, NULL, 0 ); 

	if( no_pack_res_size == 0 )
	{
		goto pack_file;
	}

	readed_res_size = 0;
	no_pack_res = ( PBYTE )malloc( no_pack_res_size ); 
	if( no_pack_res == NULL )
	{
		goto _return; 
	}

	res_cur = no_pack_res;
	
	readed_size = read_type_res( 0x3, res_cur, readed_res_size );
	readed_res_size += readed_size;
	res_cur += readed_size;

	readed_size = read_type_res( 0x0e, res_cur, readed_res_size );
	readed_res_size += readed_size;
	res_cur += readed_size;

	readed_size = read_type_res( 0x10, res_cur, readed_res_size );
	readed_res_size += readed_size;
	res_cur += readed_size;
	
	readed_size = read_type_res( 0x18, res_cur, readed_res_size ); 

pack_file:
	ret = pack_pe_file( out_file_name ); 
	if( FALSE == ret )
	{
		return ret; 
	}

	ret = gen_shell_code(); 
	if( FALSE == ret )
	{
		return ret; 
	}

	ret = set_chk_sum( out_file_name ); 
	if( FALSE == ret )
	{
		return ret; 
	}	
	
	DBGPRINT( ( "depend_module:%X\n", depend_module ) );
	DBGPRINT( ( "mem_alloc_func_name:%X\n", mem_alloc_func_name ) );
	DBGPRINT( ( "mem_free_func_name:%X\n", mem_free_func_name ) );

	DBGPRINT( ( "pack_infos:%X\n", pack_infos ) );

	/*
	for(int i=0;i<6;i++)
	{
		DBGPRINT(("shellinfo:%X\n",shell_infos[i]);

	}*/

_return:
	SAFE_RELEASE_MEM( no_pack_res ); 
	no_pack_res_size = 0; 

	return 0;
}

