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

#ifndef DEPACKS_H_INCLUDED
#define DEPACKS_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifndef APLIB_ERROR
# define APLIB_ERROR (-1)
#endif

/* function prototype */
unsigned int aP_depack_safe(const void *source,
                            unsigned int srclen,
                            void *destination,
                            unsigned int dstlen);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DEPACKS_H_INCLUDED */
