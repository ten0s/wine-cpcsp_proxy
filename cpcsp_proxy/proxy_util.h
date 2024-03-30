/*
 * Copyright 2024 Dmitry Klionsky (for Security Code)
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

#ifndef __PROXY_UTIL_H__
#define __PROXY_UTIL_H__

#include <stdint.h>

//
// Duplicates and converts the given wide string.
// If pwszStr is NULL, dup_uint16_to_uint32 ignores
// the parameter and return NULL.
// To free the memory, use the free function. 
// 
uint32_t *dup_uint16_to_uint32(const uint16_t *pwszStr);

#endif // __PROXY_UTIL_H__
