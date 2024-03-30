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
