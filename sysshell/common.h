#ifndef __COMMON_H__
#define __COMMON_H__

//#define _PRINT_DEBUG
//#define _RING3_TEST
//#define _BP_DEBUG
//D:\AntiArp\sysshell\xp_sys\ntfs.sys D:\AntiArp\sysshell\xp_sys\New\ntfs.sys
//D:\AntiArp\output\i386\AntiArp.sys D:\AntiArp\output\i386\NEW\AntiArp.sys
//D:\AntiArp\SevenLayersFW\bin\debug\i386\sevenfw.sys D:\AntiArp\SevenLayersFW\bin\debug\i386\NEW\sevenfw.sys
//E:\WinDDK\7600.16385.1\src\general\cancel\sys\objchk_wxp_x86\i386\cancel.sys E:\WinDDK\7600.16385.1\src\general\cancel\sys\objchk_wxp_x86\new\cancel.sys
//E:\WinDDK\7600.16385.1\src\general\cancel\sys\objchk_wxp_x86\i386\DIYTools.exe E:\WinDDK\7600.16385.1\src\general\cancel\sys\objchk_wxp_x86\i386\DIYTools2.exe
//E:\WinDDK\7600.16385.1\src\general\event\wdm\objchk_wxp_x86\i386\event.sys E:\WinDDK\7600.16385.1\src\general\event\wdm\objchk_wxp_x86\i386\event2.sys
#ifdef _RING3_TEST
#include <assert.h>
#define ASSERT( x ) assert( x )
#else
//#define DBG 1
#endif

#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <stdio.h>

#define ARRAY_SIZE( arr ) ( sizeof( arr ) / sizeof( arr[ 0 ] ) )

#define SAFE_RELEASE_MEM( mem ) if( mem != NULL ) { free( mem ); mem = NULL; } 

#ifdef _DEBUG
#ifdef _WIN32
#define DBGPRINT( _x_ ) printf _x_ 
#else
#define DBGPRINT( _x_ ) DbgPrint _x_
#endif
#else
#ifdef _WIN32
#define DBGPRINT( _x_ ) 
#else
#define DBGPRINT( _x_ ) 
#endif
#endif

#define PACK_FILE_SECTION_FLAGS 0xE0000040
#define	SHELL_SECTION_INDEX 2
#define PACK_DATA_SECTION_INDEX 1
#define UNPACK_SPACE_SECTION_INDEX 0
#define REMAIN_SECTION_NUM 3

#define INLINE __inline

#endif //__COMMON_H__