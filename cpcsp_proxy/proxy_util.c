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

#include <stddef.h>
#include <stdlib.h>
#include <windows.h>
#include "proxy_util.h"

uint32_t *dup_uint16_to_uint32(const uint16_t *pwszStr)
{
    uint32_t *pwwszStr = NULL;

    if (pwszStr)
    {
        size_t lenW = lstrlenW(pwszStr) + 1;
        pwwszStr = calloc(lenW, sizeof(uint32_t));
        for (size_t i = 0; i < lenW; i++)
        {
            pwwszStr[i] = pwszStr[i];
        }
    }

    return pwwszStr;
}

void conv_uint32_to_uint16(uint32_t *pwwszStr)
{
    if (!pwwszStr) return;

    uint32_t *src = pwwszStr;
    uint16_t *dst = (uint16_t *)pwwszStr;

    size_t i = 0;
    while (src[i]) {
        dst[i] = (uint16_t)src[i];
        i++;
    }
    dst[i] = 0;
}
