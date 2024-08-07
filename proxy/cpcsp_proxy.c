/*
 * Copyright (C) 2018 Dmitry Timoshkov (for Etersoft)
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "wincrypt.h"
#include "winnls.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(cpcsp_proxy);

#ifdef __linux__
  #ifdef __x86_64__
    #define SONAME_LIBSSP "/opt/cprocsp/lib/amd64/libssp.so"
  #else
    #define SONAME_LIBSSP "/opt/cprocsp/lib/ia32/libssp.so"
  #endif
#endif

#ifdef __APPLE__
  #define SONAME_LIBSSP "/opt/cprocsp/lib/libssp.dylib"
#endif

static void *libssp_handle;

//
// CryptoPro uses default calling convention on Linux and MacOS
//

static BOOL (*pCryptAcquireContextA)(HCRYPTPROV *,LPCSTR,LPCSTR,DWORD,DWORD);
static BOOL (*pCryptReleaseContext)(HCRYPTPROV,ULONG_PTR);
static BOOL (*pCryptSetProvParam)(HCRYPTPROV,DWORD,const BYTE *,DWORD);
static BOOL (*pCryptGetProvParam)(HCRYPTPROV,DWORD,BYTE *,DWORD *,DWORD);
static BOOL (*pCryptCreateHash)(HCRYPTPROV,ALG_ID,HCRYPTKEY,DWORD,HCRYPTHASH *);
static BOOL (*pCryptDestroyHash)(HCRYPTHASH);
static BOOL (*pCryptDuplicateHash)(HCRYPTHASH,DWORD *,DWORD,HCRYPTHASH *);
static BOOL (*pCryptSetHashParam)(HCRYPTHASH,DWORD,const BYTE *,DWORD);
static BOOL (*pCryptGetHashParam)(HCRYPTHASH,DWORD,BYTE *pbData,DWORD *,DWORD);
static BOOL (*pCryptGenKey)(HCRYPTPROV,ALG_ID,DWORD,HCRYPTKEY *);
static BOOL (*pCryptGetUserKey)(HCRYPTPROV,DWORD,HCRYPTKEY *);
static BOOL (*pCryptExportKey)(HCRYPTKEY,HCRYPTKEY,DWORD,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptImportKey)(HCRYPTPROV,const BYTE *,DWORD,HCRYPTKEY,DWORD,HCRYPTKEY *);
static BOOL (*pCryptDestroyKey)(HCRYPTKEY);
static BOOL (*pCryptDuplicateKey)(HCRYPTKEY,DWORD *,DWORD,HCRYPTKEY *);
static BOOL (*pCryptSetKeyParam)(HCRYPTKEY,DWORD,const BYTE *,DWORD);
static BOOL (*pCryptGetKeyParam)(HCRYPTKEY,DWORD,BYTE *,DWORD *,DWORD);
static BOOL (*pCryptDeriveKey)(HCRYPTPROV,ALG_ID,HCRYPTHASH,DWORD,HCRYPTKEY *);
static BOOL (*pCryptGenRandom)(HCRYPTPROV,DWORD,BYTE *);
static BOOL (*pCryptEncrypt)(HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE *,DWORD *,DWORD);
static BOOL (*pCryptDecrypt)(HCRYPTKEY,HCRYPTHASH,BOOL,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptHashData)(HCRYPTHASH,const BYTE *,DWORD,DWORD);
static BOOL (*pCryptHashSessionKey)(HCRYPTHASH,HCRYPTKEY,DWORD);
static BOOL (*pCryptSignHashA)(HCRYPTHASH,DWORD,LPCSTR,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptSignHashW)(HCRYPTHASH,DWORD,LPCWSTR,DWORD,BYTE *,DWORD *);
static BOOL (*pCryptVerifySignatureW)(HCRYPTHASH,const BYTE *,DWORD,HCRYPTKEY,LPCWSTR,DWORD);
static BOOL (*pCryptGetDefaultProviderA)(DWORD,DWORD *,DWORD,LPSTR,DWORD *);
static BOOL (*pGetLastError)(void);

static BOOL (*pRNetConvertPublicKeyInfo)(DWORD,CERT_PUBLIC_KEY_INFO *,ALG_ID,DWORD,BYTE **,DWORD *);
static BOOL (*pRNetEncodePublicKeyAndParameters)(DWORD,LPSTR,BYTE *,DWORD,DWORD,void *,BYTE **,DWORD *,BYTE **,DWORD *);
static BOOL (*pCryptEncodeObjectEx)(DWORD,LPCSTR,const void *,DWORD,PCRYPT_ENCODE_PARA,void *,DWORD *);
static BOOL (*pCryptDecodeObjectEx)(DWORD,LPCSTR,const BYTE *,DWORD,DWORD,PCRYPT_DECODE_PARA,void *,DWORD *);

static BOOL load_cpcsp(void)
{
    if (!(libssp_handle = dlopen(SONAME_LIBSSP, RTLD_NOW)))
    {
        FIXME("failed to load %s (%s)\n", SONAME_LIBSSP, dlerror());
        return FALSE;
    }
#define LOAD_FUNCPTR(f) \
    if ((p##f = dlsym(libssp_handle, #f)) == NULL) \
    { \
        FIXME("%s not found in %s\n", #f, SONAME_LIBSSP); \
        libssp_handle = NULL; \
        return FALSE; \
    }
    LOAD_FUNCPTR(CryptAcquireContextA);
    LOAD_FUNCPTR(CryptReleaseContext);
    LOAD_FUNCPTR(CryptSetProvParam);
    LOAD_FUNCPTR(CryptGetProvParam);
    LOAD_FUNCPTR(CryptCreateHash);
    LOAD_FUNCPTR(CryptDestroyHash);
    LOAD_FUNCPTR(CryptDuplicateHash);
    LOAD_FUNCPTR(CryptSetHashParam);
    LOAD_FUNCPTR(CryptGetHashParam);
    LOAD_FUNCPTR(CryptGenKey);
    LOAD_FUNCPTR(CryptGetUserKey);
    LOAD_FUNCPTR(CryptExportKey);
    LOAD_FUNCPTR(CryptImportKey);
    LOAD_FUNCPTR(CryptDestroyKey);
    LOAD_FUNCPTR(CryptDuplicateKey);
    LOAD_FUNCPTR(CryptSetKeyParam);
    LOAD_FUNCPTR(CryptGetKeyParam);
    LOAD_FUNCPTR(CryptDeriveKey);
    LOAD_FUNCPTR(CryptGenRandom);
    LOAD_FUNCPTR(CryptEncrypt);
    LOAD_FUNCPTR(CryptDecrypt);
    LOAD_FUNCPTR(CryptHashData);
    LOAD_FUNCPTR(CryptHashSessionKey);
    LOAD_FUNCPTR(CryptSignHashA);
    LOAD_FUNCPTR(CryptSignHashW);
    LOAD_FUNCPTR(CryptVerifySignatureW);
    LOAD_FUNCPTR(CryptGetDefaultProviderA);
    LOAD_FUNCPTR(GetLastError);
    LOAD_FUNCPTR(RNetConvertPublicKeyInfo);
    LOAD_FUNCPTR(RNetEncodePublicKeyAndParameters);
    LOAD_FUNCPTR(CryptEncodeObjectEx);
    LOAD_FUNCPTR(CryptDecodeObjectEx);
#undef LOAD_FUNCPTR

    return TRUE;
}

static void unload_cpcsp(void)
{
    dlclose(libssp_handle);
    libssp_handle = NULL;
}

/* Win32 */
static LPVOID (WINAPI *orig_CryptMemAlloc)(ULONG);

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        if (!load_cpcsp()) return FALSE;
        orig_CryptMemAlloc = (void *)GetProcAddress(GetModuleHandleA("crypt32.dll"), "CryptMemAlloc");
        DisableThreadLibraryCalls(hinst);
        break;

    case DLL_PROCESS_DETACH:
        unload_cpcsp();
        break;
    }
    return TRUE;
}

BOOL WINAPI CryptDllConvertPublicKeyInfo(DWORD type, CERT_PUBLIC_KEY_INFO *info, ALG_ID algid,
                                         DWORD flags, BYTE **data, DWORD *size)
{
    BOOL ret;

    TRACE("(%08x,%p,%04x,%08x,%p,%p)\n", type, info, algid, flags, data, size);

    if (!pRNetConvertPublicKeyInfo)
    {
        FIXME("stub\n");
        return FALSE;
    }

    ret = pRNetConvertPublicKeyInfo(type, info, algid, flags, data, size);
    if (!ret)
    {
        SetLastError(pGetLastError());
        return FALSE;
    }

    if (data)
    {
        BYTE *cp_data = *data;

        *data = orig_CryptMemAlloc(*size);
        if (!*data)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }

        memcpy(*data, cp_data, *size);
        free(cp_data);
    }

    return TRUE;
}

BOOL WINAPI CryptDllEncodePublicKeyAndParameters(DWORD type, LPSTR oid, BYTE *pubkey, DWORD pubkey_size,
                                                 DWORD flags, void *aux_info, BYTE **key_data, DWORD *key_size,
                                                 BYTE **key_params, DWORD *key_params_size)
{
    BOOL ret;

    TRACE("(%08x,%s,%p,%08x,%08x,%p,%p,%p,%p,%p)\n", type, debugstr_a(oid), pubkey, pubkey_size, flags,
          aux_info, key_data, key_size, key_params, key_params_size);

    if (!pRNetEncodePublicKeyAndParameters)
    {
        FIXME("stub\n");
        return FALSE;
    }

    ret = pRNetEncodePublicKeyAndParameters(type, oid, pubkey, pubkey_size, flags, aux_info,
                                            key_data, key_size, key_params, key_params_size);

    if (!ret)
    {
        SetLastError(pGetLastError());
        return FALSE;
    }

    TRACE("got key %p,%u, params %p,%u\n", *key_data, *key_size, *key_params, *key_params_size);

    if (key_data && *key_data)
    {
        BYTE *cp_data = *key_data;

        *key_data = orig_CryptMemAlloc(*key_size);
        if (!*key_data)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }

        memcpy(*key_data, cp_data, *key_size);
        free(cp_data);
    }

    if (key_params && *key_params)
    {
        BYTE *cp_params = *key_params;

        *key_params = orig_CryptMemAlloc(*key_params_size);
        if (!*key_params)
        {
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }

        memcpy(*key_params, cp_params, *key_params_size);
        free(cp_params);
    }

    return TRUE;
}

BOOL WINAPI CryptDllEncodeObjectEx(DWORD dwCertEncodingType,
                                   LPCSTR lpszStructType,
                                   const void *pvStructInfo,
                                   DWORD dwFlags,
                                   PCRYPT_ENCODE_PARA pEncodePara,
                                   void *pvEncoded,
                                   DWORD *pcbEncoded)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptEncodeObjectEx(dwCertEncodingType,
                               lpszStructType,
                               pvStructInfo,
                               dwFlags,
                               pEncodePara,
                               pvEncoded,
                               pcbEncoded);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CryptDllDecodeObjectEx(DWORD dwCertEncodingType,
                                   LPCSTR lpszStructType,
                                   const BYTE *pbEncoded,
                                   DWORD cbEncoded,
                                   DWORD dwFlags,
                                   PCRYPT_DECODE_PARA pDecodePara,
                                   void *pvStructInfo,
                                   DWORD *pcbStructInfo)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptDecodeObjectEx(dwCertEncodingType,
                               lpszStructType,
                               pbEncoded,
                               cbEncoded,
                               dwFlags,
                               pDecodePara,
                               pvStructInfo,
                               pcbStructInfo);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CPAcquireContext(HCRYPTPROV *prov, LPSTR container, DWORD flags, VTableProvStruc *vt)
{
    BOOL ret;

    TRACE("%p,%s,%s,%u,%08x\n", prov, debugstr_a(container), debugstr_a(vt->pszProvName), vt->dwProvType, flags);

    /* Crypto-Pro doesn't have the REGISTRY reader under Linux, so
     * 1. either add an alias using
     * /opt/cprocsp/sbin/amd64/cpconfig -hardware reader -add HDIMAGE -name REGISTRY
     * (for some reason the alias doesn't work for me)
     * or
     * 2. replace REGISTRY\\ by HDIMAGE\\. (like the below code does)
     */
    if (container && CompareStringA(LOCALE_NEUTRAL, LOCALE_USE_CP_ACP | NORM_IGNORECASE, container, 9, "REGISTRY\\", 9) == CSTR_EQUAL)
    {
        char hdimage_cont[MAX_PATH];
        char *p = strchr(container, '\\');

        if (strlen(container) + 1 >= MAX_PATH)
            FIXME("contaner name %s exceeds MAX_PATH\n", debugstr_a(container));

        /* Crypto-Pro doesn't have the REGISTRY reader under Linux */
        lstrcpyA(hdimage_cont, "HDIMAGE");
        lstrcatA(hdimage_cont, p);

        TRACE("%p,%s,%s,%u,%08x\n", prov, debugstr_a(hdimage_cont), debugstr_a(vt->pszProvName), vt->dwProvType, flags);
        ret = pCryptAcquireContextA(prov, hdimage_cont, vt->pszProvName, vt->dwProvType, flags);
        if (!ret) SetLastError(pGetLastError());

        return ret;
    }

    ret = pCryptAcquireContextA(prov, container, vt->pszProvName, vt->dwProvType, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPReleaseContext(HCRYPTPROV prov, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08x)\n", prov, flags);

    ret = pCryptReleaseContext(prov, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPSetProvParam(HCRYPTPROV prov, DWORD param, BYTE *data, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08x,%p,%08x)\n", prov, param, data, flags);

    ret = pCryptSetProvParam(prov, param, data, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPGetProvParam(HCRYPTPROV prov, DWORD param, BYTE *data, DWORD *len, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08x,%p,%p,%08x)\n", prov, param, data, len, flags);

    ret = pCryptGetProvParam(prov, param, data, len, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPCreateHash(HCRYPTPROV prov, ALG_ID algid, HCRYPTKEY key,
                         DWORD flags, HCRYPTHASH *hash)
{
    BOOL ret;

    TRACE("%08lx,%08x,%08lx,%08x,%p\n", prov, algid, key, flags, hash);

    ret = pCryptCreateHash(prov, algid, key, flags, hash);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPDestroyHash(HCRYPTPROV prov, HCRYPTHASH hash)
{
    BOOL ret;

    TRACE("%08lx,%08lx\n", prov, hash);

    ret = pCryptDestroyHash(hash);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPDuplicateHash(HCRYPTPROV prov, HCRYPTHASH hash, DWORD *reserved,
                            DWORD flags, HCRYPTHASH *newhash)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%p,%08x,%p)\n", prov, hash, reserved, flags, newhash);

    ret = pCryptDuplicateHash(hash, reserved, flags, newhash);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPSetHashParam(HCRYPTPROV prov, HCRYPTHASH hash, DWORD param,
                           BYTE *data, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08x,%p,%08x\n", prov, hash, param, data, flags);

    ret = pCryptSetHashParam(hash, param, data, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPGetHashParam(HCRYPTPROV prov, HCRYPTHASH hash, DWORD param, BYTE *data,
                           DWORD *len, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08x,%p,%p,%08x\n", prov, hash, param, data, len, flags);

    ret = pCryptGetHashParam(hash, param, data, len, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPGenKey(HCRYPTPROV prov, ALG_ID algid, DWORD flags, HCRYPTKEY *key)
{
    BOOL ret;

    TRACE("%08lx,%08x,%08x,%p\n", prov, algid, flags, key);

    ret = pCryptGenKey(prov, algid, flags, key);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPGetUserKey(HCRYPTPROV prov, DWORD keyspec, HCRYPTKEY *key)
{
    BOOL ret;

    TRACE("%08lx,%08x,%p)\n", prov, keyspec, key);

    ret = pCryptGetUserKey(prov, keyspec, key);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPExportKey(HCRYPTPROV prov, HCRYPTKEY key, HCRYPTKEY pubkey,
                        DWORD type, DWORD flags, BYTE *data, DWORD *len)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08lx,%08x,%08x,%p,%p\n", prov, key, pubkey, type, flags, data, len);

    ret = pCryptExportKey(key, pubkey, type, flags, data, len);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPImportKey(HCRYPTPROV prov, const BYTE *data, DWORD len,
                        HCRYPTKEY pubkey, DWORD flags, HCRYPTKEY *key)
{
    BOOL ret;

    TRACE("%08lx,%p,%u,%08lx,%08x,%p\n", prov, data, len, pubkey, flags, key);

    ret = pCryptImportKey(prov, data, len, pubkey, flags, key);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPDestroyKey(HCRYPTPROV prov, HCRYPTKEY key)
{
    BOOL ret;

    TRACE("%08lx,%08lx)\n", prov, key);

    ret = pCryptDestroyKey(key);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPDuplicateKey(HCRYPTPROV prov, HCRYPTKEY key, DWORD *reserved,
                           DWORD flags, HCRYPTKEY *newkey)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%p,%08x,%p\n", prov, key, reserved, flags, newkey);

    ret = pCryptDuplicateKey(key, reserved, flags, newkey);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPSetKeyParam(HCRYPTPROV prov, HCRYPTKEY key, DWORD param, BYTE *data, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08x,%p,%08x)\n", prov, key, param, data, flags);

    ret = pCryptSetKeyParam(key, param, data, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPGetKeyParam(HCRYPTPROV prov, HCRYPTKEY key, DWORD param, BYTE *data,
                          DWORD *len, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08x,%p,%p,%08x)\n", prov, key, param, data, len, flags);

    ret = pCryptGetKeyParam(key, param, data, len, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPDeriveKey(HCRYPTPROV prov, ALG_ID algid, HCRYPTHASH data,
                        DWORD flags, HCRYPTKEY *key)
{
    BOOL ret;

    TRACE("%08lx,%08x,%08lx,%08x,%p\n", prov, algid, data, flags, key);

    ret = pCryptDeriveKey(prov, algid, data, flags, key);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPGenRandom(HCRYPTPROV prov, DWORD len, BYTE *buffer)
{
    BOOL ret;

    TRACE("%08lx,%u,%p)\n", prov, len, buffer);

    ret = pCryptGenRandom(prov, len, buffer);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPEncrypt(HCRYPTPROV prov, HCRYPTKEY key, HCRYPTHASH hash, BOOL final,
                      DWORD flags, BYTE *data, DWORD *datalen, DWORD buflen)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08lx,%d,%08x,%p,%p,%u\n", prov, key, hash, final, flags, data, datalen, buflen);

    ret = pCryptEncrypt(key, hash, final, flags, data, datalen, buflen);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPDecrypt(HCRYPTPROV prov, HCRYPTKEY key, HCRYPTHASH hash, BOOL final,
                      DWORD flags, BYTE *data, DWORD *len)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08lx,%d,%08x,%p,%p\n", prov, key, hash, final, flags, data, len);

    ret = pCryptDecrypt(key, hash, final, flags, data, len);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPHashData(HCRYPTPROV prov, HCRYPTHASH hash, const BYTE *data, DWORD len, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%p,%u,%08x)\n", prov, hash, data, len, flags);

    ret = pCryptHashData(hash, data, len, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPHashSessionKey(HCRYPTPROV prov, HCRYPTHASH hash, HCRYPTKEY key, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08lx,%08x)\n", prov, hash, key, flags);

    ret = pCryptHashSessionKey(hash, key, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}

BOOL WINAPI CPSignHash(HCRYPTPROV prov, HCRYPTHASH hash, DWORD keyspec, LPCWSTR description,
                       DWORD flags, BYTE *signature, DWORD *len)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%08x,%s,%08x,%p,%p\n",
        prov, hash, keyspec, debugstr_w(description), flags, signature, len);

    TRACE("IN: %p len %u\n", signature, *len);

    ret = pCryptSignHashA(hash, keyspec, NULL, flags, signature, len);
    if (!ret) SetLastError(pGetLastError());

    TRACE("OUT: %p len %u, ret %d, error %#x\n", signature, *len, ret, pGetLastError());

    return ret;
}

BOOL WINAPI CPVerifySignature(HCRYPTPROV prov, HCRYPTHASH hash, const BYTE *signature, DWORD len,
                              HCRYPTKEY pubkey, LPCWSTR description, DWORD flags)
{
    BOOL ret;

    TRACE("%08lx,%08lx,%p,%u,%08lx,%s,%08x\n",
        prov, hash, signature, len, pubkey, debugstr_w(description), flags);

    ret = pCryptVerifySignatureW(hash, signature, len, pubkey, description, flags);
    if (!ret) SetLastError(pGetLastError());

    return ret;
}
