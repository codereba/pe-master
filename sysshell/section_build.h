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

void get_org_sect_hdrs()
{
	org_sect_size = sizeof( IMAGE_SECTION_HEADER ) * img_sect_num;
	org_sect_hdrs = malloc(org_sect_size ); 
	if( NULL == org_sect_hdrs )
	{
		return; 
	}

	memcpy( org_sect_hdrs, img_section_hdrs, org_sect_size );

	return;
}


/*-------------------------------------------------------------*/
/*  valid_data_size                                   －     */
/* 搜索并去掉尾部无用的零字节，重新计算区块的大小             */
/*-------------------------------------------------------------*/

UINT valid_data_size(PCHAR sect_data, UINT sect_size)
{
	PCHAR _data; 
	UINT _size; 

	return sect_size; 

	if( IsBadReadPtr( sect_data, sect_size ) ) 
	{
		return sect_size;
	}
	
	_data = &sect_data[ sect_size - 1 ];
	_size = sect_size;
	
	while( _size > 0 && *_data == 0)
	{
		_data --;
		_size --;
	}
	
	return _size;
}
