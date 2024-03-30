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
