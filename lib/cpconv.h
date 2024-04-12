/*
 * Copyright (C) 2024 Dmitry Klionsky (for Security Code)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __CP_CONV_H__
#define __CP_CONV_H__

#include <stdint.h>

//
// _WIN64 only!
//

//
// Convertion Notice
//
// Windows
//
// sizeof(LONG)  == 2
// sizeof(WCHAR) == 2
//
// Linux
//
// sizeof(LONG)  == 4
// sizeof(WCHAR) == 4
//
// Windows: WCHAR == wchar_t == uint16_t => wchar2_t
// Linux  : WCHAR == wchar_t == uint32_t => wchar4_t
//
// Therefore, all Windows null-terminated Unicode strings in wchar2_t*
// must be converted to wchar4_t* using the dup_wc2s_to_wc4s function
// and back using the conv_wc4s_to_wc2s function.
//

typedef uint16_t wchar2_t;
typedef uint32_t wchar4_t;

//
// Determine the length of the given wchar2_t* string
//
size_t wc2slen(const wchar2_t *pwszStr);

//
// Determine the length of the given wchar4_t* string
//
size_t wc4slen(const wchar4_t *pwwszStr);

//
// Duplicates the wchar4_t* string.
// If pwwszStr is NULL, wc4sdup ignores
// the parameter and return NULL.
// To free the memory, use the free function.
//
wchar4_t *wc4sdup(const wchar4_t *pwwszStr);

//
// Duplicates and converts the wchar2_t* string
// to wchar4_t* string.
// If pwszStr is NULL, dup_wc2s_to_wc4s ignores
// the parameter and return NULL.
// To free the memory, use the free function.
//
wchar4_t *dup_wc2s_to_wc4s(const wchar2_t *pwszStr);

//
// Converts the given wchar4_t* string
// to wchar2_t* string in place.
// If pwwszStr is NULL, conv_wc4s_to_wc2s ignores
// the parameter and return NULL.
//
void conv_wc4s_to_wc2s(wchar4_t *pwwszStr);

#endif // __CP_CONV_H__
