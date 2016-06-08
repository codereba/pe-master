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

//CalcPECheckSum PROC lpBaseAddr:DWORD,dwFileSize:DWORD
//        LOCAL  CheckSum:DWORD
//        pushad
//        mov    ecx,dwFileSize
//        inc    ecx
//        shr    ecx,1
//        xor    eax,eax
//        clc
//        mov    esi,lpBaseAddr
//    cal_checksum:
//        adc    ax,word ptr [esi]
//        inc    esi
//        inc    esi
//        loop   cal_checksum
//        mov    ebx,dwFileSize
//        add    eax,ebx
//        mov    CheckSum,eax
//        popad
//        mov    eax,CheckSum 
//        ret
//CalcPECheckSum endp


USHORT calc_chk_sum( ULONG partial_sum, 
	   PUSHORT data, 
	   ULONG length )
{
	while( length-- )
	{
		partial_sum += *data++; 
		partial_sum = ( partial_sum >> 16 ) + ( partial_sum & 0xffff );
	}

	return ( USHORT )( ( ( partial_sum >> 16 ) + partial_sum ) & 0xffff );
}

// ; __stdcall ChkSum(x, x, x)
//PAGE:004CFB9A                         _ChkSum@12      proc near               ; CODE XREF: LdrVerifyMappedImageMatchesChecksum(x,x)+15p
//PAGE:004CFB9A
//PAGE:004CFB9A                         arg_0           = dword ptr  8
//PAGE:004CFB9A                         arg_4           = dword ptr  0Ch
//PAGE:004CFB9A                         arg_8           = dword ptr  10h
//PAGE:004CFB9A
//PAGE:004CFB9A 8B FF                                   mov     edi, edi
//PAGE:004CFB9C 55                                      push    ebp
//PAGE:004CFB9D 8B EC                                   mov     ebp, esp
//PAGE:004CFB9F 8B 4D 10                                mov     ecx, [ebp+arg_8]
//PAGE:004CFBA2 85 C9                                   test    ecx, ecx
//PAGE:004CFBA4 74 24                                   jz      short loc_4CFBCA
//PAGE:004CFBA6 8B 45 0C                                mov     eax, [ebp+arg_4]
//PAGE:004CFBA9 56                                      push    esi
//PAGE:004CFBAA
//PAGE:004CFBAA                         loc_4CFBAA:                             ; CODE XREF: ChkSum(x,x,x)+2Dj
//PAGE:004CFBAA 0F B7 10                                movzx   edx, word ptr [eax]
//PAGE:004CFBAD 01 55 08                                add     [ebp+arg_0], edx
//PAGE:004CFBB0 8B 55 08                                mov     edx, [ebp+arg_0]
//PAGE:004CFBB3 8B 75 08                                mov     esi, [ebp+arg_0]
//PAGE:004CFBB6 40                                      inc     eax
//PAGE:004CFBB7 C1 EA 10                                shr     edx, 10h
//PAGE:004CFBBA 81 E6 FF FF 00 00                       and     esi, 0FFFFh
//PAGE:004CFBC0 03 D6                                   add     edx, esi
//PAGE:004CFBC2 40                                      inc     eax
//PAGE:004CFBC3 49                                      dec     ecx
//PAGE:004CFBC4 89 55 08                                mov     [ebp+arg_0], edx
//PAGE:004CFBC7 75 E1                                   jnz     short loc_4CFBAA
//PAGE:004CFBC9 5E                                      pop     esi
//PAGE:004CFBCA
//PAGE:004CFBCA                         loc_4CFBCA:                             ; CODE XREF: ChkSum(x,x,x)+Aj
//PAGE:004CFBCA 8B 45 08                                mov     eax, [ebp+arg_0]
//PAGE:004CFBCD C1 E8 10                                shr     eax, 10h
//PAGE:004CFBD0 03 45 08                                add     eax, [ebp+arg_0]
//PAGE:004CFBD3 5D                                      pop     ebp
//PAGE:004CFBD4 C2 0C 00                                retn    0Ch
//PAGE:004CFBD4                         _ChkSum@12      endp

//计算校验和
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
INT32 set_chk_sum( LPCSTR file_name )
{
	INT32 ret; 
	DWORD file_size;
	PWORD check_sum;
	HANDLE hfile; 
	HANDLE hfile_map; 
	LPVOID _img_base; 
	USHORT partial_sum;
	PIMAGE_NT_HEADERS32 nt_hdrs;
	PIMAGE_DOS_HEADER dos_hdr;

	ASSERT( file_name != NULL ); 

	hfile = CreateFile( file_name, 
		GENERIC_READ |GENERIC_WRITE, 
		0, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL );

	if( hfile == INVALID_HANDLE_VALUE )
	{
		DBGPRINT( ("create file failed\n" ) );
		ret = FALSE; 
		goto _return; 
	}

	file_size = GetFileSize( hfile, NULL );
	
	hfile_map = CreateFileMapping( hfile, 
		NULL, 
		PAGE_READWRITE, 
		NULL, 
		NULL, 
		NULL );

	if( hfile_map == INVALID_HANDLE_VALUE )
	{
		DBGPRINT( ("create file mapping failed\n" ) );
		ret = FALSE; 
		goto _return; 
	}
	
	_img_base = MapViewOfFile( hfile_map, FILE_MAP_WRITE, 0, 0, 0 );
	if( _img_base == NULL )
	{
		DBGPRINT( ("map view of file failed\n" ) );
		ret = FALSE; 
		goto _return; 
	}

	partial_sum = calc_chk_sum( 0, ( PUSHORT )_img_base, ( file_size + 1 ) >> 1 );

	dos_hdr = ( PIMAGE_DOS_HEADER )_img_base;
	nt_hdrs = ( PIMAGE_NT_HEADERS )( dos_hdr->e_lfanew + ( DWORD )_img_base );
	if( nt_hdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC )
	{
		check_sum = ( PUSHORT )&( ( ( PIMAGE_NT_HEADERS32 )nt_hdrs )->OptionalHeader.CheckSum );
		partial_sum -= ( partial_sum < check_sum[0] );
		partial_sum -= check_sum[ 0 ];
		partial_sum -= ( partial_sum < check_sum[1] );
		partial_sum -= check_sum[ 1 ];
		
	}

	nt_hdrs->OptionalHeader.CheckSum = ( DWORD )partial_sum + file_size;
	
_return:

	if( _img_base != NULL )
	{
		FlushViewOfFile( _img_base, 0 ); 
		UnmapViewOfFile( _img_base ); 
	}

	if( hfile_map != INVALID_HANDLE_VALUE )
		CloseHandle( hfile_map ); 
	
	if( hfile != INVALID_HANDLE_VALUE ) 
		CloseHandle( hfile ); 

	return TRUE;
}