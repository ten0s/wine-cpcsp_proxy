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

#include <stddef.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>

#include "cpconv.h"

size_t wc2slen(const wchar2_t *pwszStr)
{
    return lstrlenW(pwszStr);
}

size_t wc4slen(const wchar4_t *pwwszStr)
{
    size_t i = 0;
    const wchar4_t *src = pwwszStr;
    while (src[i]) { i++; }
    return i;
}

wchar4_t *wc4sdup(const wchar4_t *pwwszStr)
{
    if (!pwwszStr) return NULL;

    size_t len = wc4slen(pwwszStr) + 1;
    wchar4_t *pwwszStr2 = calloc(len, sizeof(wchar4_t));
    memcpy(pwwszStr2, pwwszStr, len * sizeof(wchar4_t));

    return pwwszStr2;
}

wchar4_t *dup_wc2s_to_wc4s(const wchar2_t *pwszStr)
{
    wchar4_t *pwwszStr = NULL;

    if (pwszStr)
    {
        size_t len = wc2slen(pwszStr) + 1;
        pwwszStr = calloc(len, sizeof(wchar4_t));
        for (size_t i = 0; i < len; i++)
        {
            pwwszStr[i] = pwszStr[i];
        }
    }

    return pwwszStr;
}

void conv_wc4s_to_wc2s(wchar4_t *pwwszStr)
{
    if (!pwwszStr) return;

    wchar4_t *src = pwwszStr;
    wchar2_t *dst = (wchar2_t *)pwwszStr;

    size_t i = 0;
    while (src[i]) {
        dst[i] = (wchar2_t)src[i];
        i++;
    }
    dst[i] = 0;
}
