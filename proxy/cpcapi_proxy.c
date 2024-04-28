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

// Windows
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
// Linux
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201102L) && !defined(__STDC_NO_THREADS__)
#  include <threads.h>
#  define THREAD_LOCAL thread_local
#else
#  define THREAD_LOCAL
#endif
// Wine
#include <wine/debug.h>

#include "../lib/cpconv.h"

WINE_DEFAULT_DEBUG_CHANNEL(cpcapi_proxy);

#ifdef __linux__
  #ifdef __x86_64__
    #define SONAME_LIBCAPI10 "/opt/cprocsp/lib/amd64/libcapi10.so"
    #define SONAME_LIBCAPI20 "/opt/cprocsp/lib/amd64/libcapi20.so"
  #else
    // Untested
    //#define SONAME_LIBCAPI10 "/opt/cprocsp/lib/ia32/libcapi10.so"
    //#define SONAME_LIBCAPI20 "/opt/cprocsp/lib/ia32/libcapi20.so"
  #endif
#endif

#ifdef __APPLE__
  #define SONAME_LIBCAPI10 "/opt/cprocsp/lib/libcapi10.dylib"
  #define SONAME_LIBCAPI20 "/opt/cprocsp/lib/libcapi20.dylib"
#endif

//
// __x86_64__ only!
//

//
// CryptoPro uses default calling convention on Linux and MacOS
//

//
// CAPI10
//

static BOOL (*pCryptEnumProvidersA)(
    DWORD dwIndex,
    DWORD *pdwReserved,
    DWORD dwFlags,
    DWORD *pdwProvType,
    LPSTR szProvName,
    DWORD *pcbProvName
);

static BOOL (*pCryptAcquireContextA)(
    HCRYPTPROV *phProv,
    const char *szContName,
    const char *szProvName,
    DWORD dwProvType,
    DWORD dwFlags
);

static BOOL (*pCryptAcquireContextW)(
    HCRYPTPROV *phProv,
    const wchar4_t *wwszContName,
    const wchar4_t *wwszProvName,
    DWORD dwProvType,
    DWORD dwFlags
);

static BOOL (*pCryptGetProvParam)(
    HCRYPTPROV hProv,
    DWORD dwParam,
    BYTE *pbData,
    DWORD *pdwDataLen,
    DWORD dwFlags
);

static BOOL (*pCryptSetProvParam)(
    HCRYPTPROV hProv,
    DWORD dwParam,
    const BYTE *pbData,
    DWORD dwFlags
);

static BOOL (*pCryptGetUserKey)(
    HCRYPTPROV hProv,
    DWORD dwKeySpec,
    HCRYPTKEY *phUserKey
);

static BOOL (*pCryptDestroyKey)(
    HCRYPTKEY hKey
);

static BOOL (*pCryptReleaseContext)(
    HCRYPTPROV hProv,
    DWORD dwFlags
);

static BOOL (*pCryptEnumOIDInfo)(
    DWORD dwGroupId,
    DWORD dwFlags,
    void *pvArg,
    PFN_CRYPT_ENUM_OID_INFO pfnEnumOIDInfo
);

static BOOL (*pGetLastError)();

//
// CAPI20
//

static BOOL (*pCryptAcquireCertificatePrivateKey)(
    PCCERT_CONTEXT pCert,
    DWORD dwFlags,
    void *pvReserved,
    HCRYPTPROV *phCryptProv,
    DWORD *pdwKeySpec,
    BOOL *pfCallerFreeProv
);

static BOOL (*pCryptEncodeObjectEx)(
    DWORD dwCertEncodingType,
    LPCSTR lpszStructType,
    const void *pvStructInfo,
    DWORD dwFlags,
    PCRYPT_ENCODE_PARA pEncodePara,
    void *pvEncoded,
    DWORD *pcbEncoded
);

static BOOL (*pCryptDecodeObjectEx)(
    DWORD dwCertEncodingType,
    LPCSTR lpszStructType,
    const BYTE *pbEncoded,
    DWORD cbEncoded,
    DWORD dwFlags,
    PCRYPT_DECODE_PARA pDecodePara,
    void *pvStructInfo,
    DWORD *pcbStructInfo
);

static BOOL (*pCryptExportPublicKeyInfo)(
    HCRYPTPROV hProv,
    DWORD dwKeySpec,
    DWORD dwCertEncodingType,
    PCERT_PUBLIC_KEY_INFO pInfo,
    DWORD *pcbInfo
);

static BOOL (*pCertComparePublicKeyInfo)(
    DWORD dwCertEncodingType,
    PCERT_PUBLIC_KEY_INFO pPublicKey1,
    PCERT_PUBLIC_KEY_INFO pPublicKey2
);

static DWORD (*pCertGetNameStringA)(
    PCCERT_CONTEXT pCertContext,
    DWORD dwType,
    DWORD dwFlags,
    void *pvTypePara,
    LPSTR pszNameString,
    DWORD cchNameString
);

static HCERTSTORE (*pCertOpenStore)(
    LPCSTR lpszStoreProvider,
    DWORD dwEncodingType,
    HCRYPTPROV hCryptProv,
    DWORD dwFlags,
    const void *pvPara
);

static HCERTSTORE (*pCertOpenSystemStoreA)(
    HCRYPTPROV hProv,
    const char *szSubsystemProtocol
);

static HCERTSTORE (*pCertOpenSystemStoreW)(
    HCRYPTPROV hProv,
    const wchar4_t *wszSubsystemProtocol
);

static BOOL (*pCertControlStore)(
    HCERTSTORE hCertStore,
    DWORD dwFlags,
    DWORD dwCtrlType,
    void const *pvCtrlPara
);

static BOOL (*pCertCloseStore)(
    HCERTSTORE hCertStore,
    DWORD dwFlags
);

static PCCERT_CONTEXT (*pCertEnumCertificatesInStore)(
    HCERTSTORE hCertStore,
    PCCERT_CONTEXT pPrevCertContext
);

static PCCERT_CONTEXT (*pCertFindCertificateInStore)(
    HCERTSTORE hCertStore,
    DWORD dwCertEncodingType,
    DWORD dwFindFlags,
    DWORD dwFindType,
    const void *pvFindPara,
    PCCERT_CONTEXT pPrevCertContext
);

static BOOL (*pCertDeleteCertificateFromStore)(
    PCCERT_CONTEXT pCertContext
);

static PCCERT_CONTEXT (*pCertGetIssuerCertificateFromStore)(
    HCERTSTORE hCertStore,
    PCCERT_CONTEXT pSubjectContext,
    PCCERT_CONTEXT pPrevIssuerContext,
    DWORD *pdwFlags
);

static PCCERT_CONTEXT (*pCertCreateCertificateContext)(
    DWORD dwCertEncodingType,
    const BYTE *pbCertEncoded,
    DWORD cbCertEncoded
);

static PCCERT_CONTEXT (*pCertDuplicateCertificateContext)(
    PCCERT_CONTEXT pCertContext
);

static DWORD (*pCertEnumCertificateContextProperties)(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId
);

static BOOL (*pCertGetCertificateContextProperty)(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId,
    void *pvData,
    DWORD *pcbData
);

static BOOL (*pCertSetCertificateContextProperty)(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId,
    DWORD dwFlags,
    const void *pvData
);

static BOOL (*pCertAddCertificateContextToStore)(
    HCERTSTORE hCertStore,
    PCCERT_CONTEXT pCertContext,
    DWORD dwAddDisposition,
    PCCERT_CONTEXT *ppStoreContext
);

static BOOL (*pCertFreeCertificateContext)(
    PCCERT_CONTEXT pCertContext
);

static BOOL (*pCertGetCertificateChain)(
    HCERTCHAINENGINE hChainEngine,
    PCCERT_CONTEXT pCertContext,
    LPFILETIME pTime,
    HCERTSTORE hAdditionalStore,
    PCERT_CHAIN_PARA pChainPara,
    DWORD dwFlags,
    LPVOID pvReserved,
    PCCERT_CHAIN_CONTEXT *ppChainContext
);

static VOID (*pCertFreeCertificateChain)(
    PCCERT_CHAIN_CONTEXT pChainContext
);

static void *libcapi10;
static void *libcapi20;

static BOOL load_cpcapi10()
{
    if (!(libcapi10 = dlopen(SONAME_LIBCAPI10, RTLD_NOW)))
    {
        FIXME("failed to load %s (%s)\n", SONAME_LIBCAPI10, dlerror());
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if ((p##f = dlsym(libcapi10, #f)) == NULL) \
    { \
        FIXME("%s not found in %s\n", #f, SONAME_LIBCAPI10); \
        libcapi10 = NULL; \
        return FALSE; \
    }
    LOAD_FUNCPTR(CryptEnumProvidersA);
    LOAD_FUNCPTR(CryptAcquireContextA);
    LOAD_FUNCPTR(CryptAcquireContextW);
    LOAD_FUNCPTR(CryptGetProvParam);
    LOAD_FUNCPTR(CryptSetProvParam);
    LOAD_FUNCPTR(CryptGetUserKey);
    LOAD_FUNCPTR(CryptDestroyKey);
    LOAD_FUNCPTR(CryptReleaseContext);
    LOAD_FUNCPTR(CryptEnumOIDInfo);
    LOAD_FUNCPTR(GetLastError);
#undef LOAD_FUNCPTR

    return TRUE;
}

static BOOL load_cpcapi20()
{
    if (!(libcapi20 = dlopen(SONAME_LIBCAPI20, RTLD_NOW)))
    {
        FIXME("failed to load %s (%s)\n", SONAME_LIBCAPI20, dlerror());
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if ((p##f = dlsym(libcapi20, #f)) == NULL) \
    { \
        FIXME("%s not found in %s\n", #f, SONAME_LIBCAPI20); \
        libcapi20 = NULL; \
        return FALSE; \
    }
    LOAD_FUNCPTR(CryptAcquireCertificatePrivateKey);
    LOAD_FUNCPTR(CryptEncodeObjectEx);
    LOAD_FUNCPTR(CryptDecodeObjectEx);
    LOAD_FUNCPTR(CryptExportPublicKeyInfo);
    LOAD_FUNCPTR(CertComparePublicKeyInfo);
    LOAD_FUNCPTR(CertGetNameStringA);
    LOAD_FUNCPTR(CertOpenStore);
    LOAD_FUNCPTR(CertOpenSystemStoreA);
    LOAD_FUNCPTR(CertOpenSystemStoreW);
    LOAD_FUNCPTR(CertControlStore);
    LOAD_FUNCPTR(CertCloseStore);
    LOAD_FUNCPTR(CertEnumCertificatesInStore);
    LOAD_FUNCPTR(CertFindCertificateInStore);
    LOAD_FUNCPTR(CertDeleteCertificateFromStore);
    LOAD_FUNCPTR(CertGetIssuerCertificateFromStore);
    LOAD_FUNCPTR(CertCreateCertificateContext);
    LOAD_FUNCPTR(CertDuplicateCertificateContext);
    LOAD_FUNCPTR(CertEnumCertificateContextProperties);
    LOAD_FUNCPTR(CertGetCertificateContextProperty);
    LOAD_FUNCPTR(CertSetCertificateContextProperty);
    LOAD_FUNCPTR(CertAddCertificateContextToStore);
    LOAD_FUNCPTR(CertFreeCertificateContext);
    LOAD_FUNCPTR(CertGetCertificateChain);
    LOAD_FUNCPTR(CertFreeCertificateChain);
#undef LOAD_FUNCPTR

    return TRUE;
}

static void unload_cpcapi10()
{
    dlclose(libcapi10);
    libcapi10 = NULL;
}

static void unload_cpcapi20()
{
    dlclose(libcapi20);
    libcapi20 = NULL;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        if (!load_cpcapi10()) return FALSE;
        if (!load_cpcapi20()) return FALSE;
        DisableThreadLibraryCalls(hinst);
        break;

    case DLL_PROCESS_DETACH:
        unload_cpcapi10();
        unload_cpcapi20();
        break;
    }
    return TRUE;
}

//
// CAPI10
//

BOOL WINAPI CP_CryptEnumProvidersA(DWORD dwIndex,
                                   DWORD *pdwReserved,
                                   DWORD dwFlags,
                                   DWORD *pdwProvType,
                                   LPSTR szProvName,
                                   DWORD *pcbProvName)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptEnumProvidersA(dwIndex,
                               pdwReserved,
                               dwFlags,
                               pdwProvType,
                               szProvName,
                               pcbProvName);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptAcquireContextA(HCRYPTPROV *phProv,
                                    LPCSTR szContName,
                                    LPCSTR szProvName,
                                    DWORD dwProvType,
                                    DWORD dwFlags)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptAcquireContextA(phProv,
                                szContName,
                                szProvName,
                                dwProvType,
                                dwFlags);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptAcquireContextW(HCRYPTPROV *phProv,
                                    LPCWSTR wszContName,
                                    LPCWSTR wszProvName,
                                    DWORD dwProvType,
                                    DWORD dwFlags)
{
    BOOL ret;
    TRACE("\n");

    //
    // wszContName and wszProvName must be converted to wchar4_t*.
    // See 'Convertion Notice' in lib/cpconv.h.
    //
    wchar4_t *wwszContName = dup_wc2s_to_wc4s(wszContName);
    wchar4_t *wwszProvName = dup_wc2s_to_wc4s(wszProvName);

    ret = pCryptAcquireContextW(phProv,
                                wwszContName,
                                wwszProvName,
                                dwProvType,
                                dwFlags);

    free(wwszContName);
    free(wwszProvName);

    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptGetProvParam(HCRYPTPROV hProv,
                                 DWORD dwParam,
                                 BYTE *pbData,
                                 DWORD *pdwDataLen,
                                 DWORD dwFlags)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptGetProvParam(hProv,
                             dwParam,
                             pbData,
                             pdwDataLen,
                             dwFlags);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptSetProvParam(HCRYPTPROV hProv,
                                 DWORD dwParam,
                                 const BYTE *pbData,
                                 DWORD dwFlags)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptSetProvParam(hProv,
                             dwParam,
                             pbData,
                             dwFlags);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptGetUserKey(HCRYPTPROV hProv,
                               DWORD dwKeySpec,
                               HCRYPTKEY *phUserKey)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptGetUserKey(hProv, dwKeySpec, phUserKey);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptDestroyKey(HCRYPTKEY hKey)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptDestroyKey(hKey);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptReleaseContext(HCRYPTPROV hProv,
                                   DWORD dwFlags)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptReleaseContext(hProv, dwFlags);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

typedef struct {
    DWORD     cbSize;
    wchar2_t *pszOID;
    wchar4_t *pwszName;
    DWORD     dwGroupId;
    ALG_ID    Algid;
    CRYPT_DATA_BLOB ExtraInfo;
} CPro_OID_INFO;

// CryptoPro implementation of CryptEnumOIDInfo
// doesn't use WINAPI for a callback.
static THREAD_LOCAL PFN_CRYPT_ENUM_OID_INFO g_pfnEnumOIDInfo;
static BOOL /*WINAPI*/ EnumOIDInfo(const CPro_OID_INFO *info, void *arg)
{
    if (!g_pfnEnumOIDInfo) return FALSE;

    //
    // pwszName must be converted to wchar2_t*.
    // See 'Convertion Notice' in lib/cpconv.h.
    //
    wchar4_t *pwwszName = wc4sdup((wchar4_t *)info->pwszName);
    wchar2_t *pwszName = (wchar2_t *)pwwszName;
    conv_wc4s_to_wc2s(pwwszName);

    CRYPT_OID_INFO winInfo = {0};
    memcpy(&winInfo, info, sizeof(*info));
    winInfo.pwszName = pwszName;

    BOOL ret = g_pfnEnumOIDInfo(&winInfo, arg);

    free(pwszName);

    return ret;
}

BOOL WINAPI CP_CryptEnumOIDInfo(DWORD dwGroupId,
                                DWORD dwFlags,
                                void *pvArg,
                                PFN_CRYPT_ENUM_OID_INFO pfnEnumOIDInfo)
{
    BOOL ret;
    TRACE("\n");

    g_pfnEnumOIDInfo = pfnEnumOIDInfo;
    ret = pCryptEnumOIDInfo(dwGroupId,
                            dwFlags,
                            pvArg,
                            (PFN_CRYPT_ENUM_OID_INFO)EnumOIDInfo);
    g_pfnEnumOIDInfo = NULL;

    if (!ret) SetLastError(pGetLastError());
    return ret;
}

//
// CAPI20
//

BOOL WINAPI CP_CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert,
                                                 DWORD dwFlags,
                                                 void *pvReserved,
                                                 HCRYPTPROV *phCryptProv,
                                                 DWORD *pdwKeySpec,
                                                 BOOL *pfCallerFreeProv)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptAcquireCertificatePrivateKey(pCert,
                                             dwFlags,
                                             pvReserved,
                                             phCryptProv,
                                             pdwKeySpec,
                                             pfCallerFreeProv);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CryptEncodeObjectEx(DWORD dwCertEncodingType,
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

BOOL WINAPI CP_CryptDecodeObjectEx(DWORD dwCertEncodingType,
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

BOOL WINAPI CP_CryptExportPublicKeyInfo(HCRYPTPROV hProv,
                                        DWORD dwKeySpec,
                                        DWORD dwCertEncodingType,
                                        PCERT_PUBLIC_KEY_INFO pInfo,
                                        DWORD *pcbInfo)
{
    BOOL ret;
    TRACE("\n");
    ret = pCryptExportPublicKeyInfo(hProv,
                                    dwKeySpec,
                                    dwCertEncodingType,
                                    pInfo,
                                    pcbInfo);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertComparePublicKeyInfo(DWORD dwCertEncodingType,
                                        PCERT_PUBLIC_KEY_INFO pPublicKey1,
                                        PCERT_PUBLIC_KEY_INFO pPublicKey2)
{
    BOOL ret;
    TRACE("\n");
    ret = pCertComparePublicKeyInfo(dwCertEncodingType,
                                    pPublicKey1,
                                    pPublicKey2);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

DWORD WINAPI CP_CertGetNameStringA(PCCERT_CONTEXT pCertContext,
                                   DWORD dwType,
                                   DWORD dwFlags,
                                   void *pvTypePara,
                                   LPSTR pszNameString,
                                   DWORD cchNameString)
{
    DWORD ret;
    TRACE("\n");
    ret = pCertGetNameStringA(pCertContext,
                              dwType,
                              dwFlags,
                              pvTypePara,
                              pszNameString,
                              cchNameString);
    return ret;
}

HCERTSTORE WINAPI CP_CertOpenStore(LPCSTR lpszStoreProvider,
                                   DWORD dwEncodingType,
                                   HCRYPTPROV hCryptProv,
                                   DWORD dwFlags,
                                   const void *pvPara)
{
    HCERTSTORE ret;
    TRACE("\n");

    void *pvParaWC4S = NULL;
    BOOL to_wc4s = FALSE;

#define IS_INTOID(x) (((ULONG_PTR)(x) >> 16) == 0)
    if (IS_INTOID(lpszStoreProvider))
    {
        if (LOWORD(lpszStoreProvider) == LOWORD(CERT_STORE_PROV_SYSTEM))
        {
            to_wc4s = TRUE;
        }
    }
    else if (strcmp(lpszStoreProvider, sz_CERT_STORE_PROV_SYSTEM) == 0)
    {
        to_wc4s = TRUE;
    }
#undef IS_INTOID

    if (to_wc4s)
    {
        //
        // pvPara containing null-terminated Unicode string
        // must be converted to wchar4_t*.
        // See 'Convertion Notice' in lib/cpconv.h.
        //
        pvParaWC4S = dup_wc2s_to_wc4s(pvPara);
    }

    ret = pCertOpenStore(lpszStoreProvider,
                         dwEncodingType,
                         hCryptProv,
                         dwFlags,
                         pvParaWC4S ? pvParaWC4S : pvPara);

    free(pvParaWC4S);

    if (!ret) SetLastError(pGetLastError());
    return ret;
}

HCERTSTORE WINAPI CP_CertOpenSystemStoreA(HCRYPTPROV hProv,
                                          LPCSTR szSubsystemProtocol)
{

    HCERTSTORE ret;
    TRACE("\n");
    ret = pCertOpenSystemStoreA(hProv, szSubsystemProtocol);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

HCERTSTORE WINAPI CP_CertOpenSystemStoreW(HCRYPTPROV hProv,
                                          LPCWSTR wszSubsystemProtocol)
{

    HCERTSTORE ret;
    TRACE("\n");

    //
    // wszSubsystemProtocol must be converted to wchar4_t*.
    // See 'Convertion Notice' in lib/cpconv.h.
    //

    wchar4_t *wwszSubsystemProtocol = dup_wc2s_to_wc4s(wszSubsystemProtocol);

    ret = pCertOpenSystemStoreW(hProv, wwszSubsystemProtocol);

    free(wwszSubsystemProtocol);

    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertControlStore(HCERTSTORE hCertStore,
                                DWORD dwFlags,
                                DWORD dwCtrlType,
                                void const *pvCtrlPara)
{
    BOOL ret;
    TRACE("\n");
    ret = pCertControlStore(hCertStore,
                            dwFlags,
                            dwCtrlType,
                            pvCtrlPara);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertCloseStore(HCERTSTORE hCertStore,
                              DWORD dwFlags)
{
    BOOL ret = TRUE;
    TRACE("\n");
    if (hCertStore)
    {
        ret = pCertCloseStore(hCertStore, dwFlags);
        if (!ret) SetLastError(pGetLastError());
    }
    return ret;
}

PCCERT_CONTEXT WINAPI CP_CertEnumCertificatesInStore(HCERTSTORE hCertStore,
                                                     PCCERT_CONTEXT pPrevCertContext)
{
    PCCERT_CONTEXT ret;
    TRACE("\n");
    ret = pCertEnumCertificatesInStore(hCertStore,
                                       pPrevCertContext);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

PCCERT_CONTEXT WINAPI CP_CertFindCertificateInStore(HCERTSTORE hCertStore,
                                                    DWORD dwCertEncodingType,
                                                    DWORD dwFindFlags,
                                                    DWORD dwFindType,
                                                    const void *pvFindPara,
                                                    PCCERT_CONTEXT pPrevCertContext)
{
    PCCERT_CONTEXT ret;
    TRACE("\n");
    ret = pCertFindCertificateInStore(hCertStore,
                                      dwCertEncodingType,
                                      dwFindFlags,
                                      dwFindType,
                                      pvFindPara,
                                      pPrevCertContext);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertDeleteCertificateFromStore(PCCERT_CONTEXT pCertContext)
{
    BOOL ret;
    TRACE("\n");
    ret = pCertDeleteCertificateFromStore(pCertContext);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

PCCERT_CONTEXT WINAPI CP_CertGetIssuerCertificateFromStore(HCERTSTORE hCertStore,
                                                           PCCERT_CONTEXT pSubjectContext,
                                                           PCCERT_CONTEXT pPrevIssuerContext,
                                                           DWORD *pdwFlags)
{
    PCCERT_CONTEXT ret;
    TRACE("\n");
    ret = pCertGetIssuerCertificateFromStore(hCertStore,
                                             pSubjectContext,
                                             pPrevIssuerContext,
                                             pdwFlags);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

PCCERT_CONTEXT WINAPI CP_CertCreateCertificateContext(DWORD dwCertEncodingType,
                                                      const BYTE *pbCertEncoded,
                                                      DWORD cbCertEncoded)
{
    PCCERT_CONTEXT ret;
    TRACE("\n");
    ret = pCertCreateCertificateContext(dwCertEncodingType,
                                        pbCertEncoded,
                                        cbCertEncoded);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

PCCERT_CONTEXT WINAPI CP_CertDuplicateCertificateContext(PCCERT_CONTEXT pCertContext)
{
    PCCERT_CONTEXT ret;
    TRACE("\n");
    ret = pCertDuplicateCertificateContext(pCertContext);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

DWORD WINAPI CP_CertEnumCertificateContextProperties(PCCERT_CONTEXT pCertContext,
                                                     DWORD dwPropId)
{
    DWORD ret;
    TRACE("\n");
    ret = pCertEnumCertificateContextProperties(pCertContext,
                                                dwPropId);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext,
                                                 DWORD dwPropId,
                                                 void *pvData,
                                                 DWORD *pcbData)
{
    BOOL ret;
    TRACE("\n");

    ret = pCertGetCertificateContextProperty(pCertContext,
                                             dwPropId,
                                             pvData,
                                             pcbData);
    switch (dwPropId) {
    case CERT_KEY_PROV_INFO_PROP_ID: {
        if (pvData) {
            //
            // pwszContainerName and pwszProvName must be converted to wchar2_t*.
            // See 'Convertion Notice' in lib/cpconv.h and
            // CP_CertSetCertificateContextProperty.
            //
            CRYPT_KEY_PROV_INFO *pKeyProvInfo = (CRYPT_KEY_PROV_INFO *)pvData;
            conv_wc4s_to_wc2s((wchar4_t *)pKeyProvInfo->pwszContainerName);
            conv_wc4s_to_wc2s((wchar4_t *)pKeyProvInfo->pwszProvName);
        }
        break;
    }
    default:
        break;
    }

    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertSetCertificateContextProperty(PCCERT_CONTEXT pCertContext,
                                                 DWORD dwPropId,
                                                 DWORD dwFlags,
                                                 const void *pvData)
{
    BOOL ret;
    TRACE("\n");

    wchar4_t *wwszContName = NULL;
    wchar4_t *wwszProvName = NULL;

    switch (dwPropId) {
    case CERT_KEY_PROV_INFO_PROP_ID: {
        if (pvData) {
            //
            // pwszContainerName and pwszProvName must be converted to wchar4_t*.
            // See 'Convertion Notice' in lib/cpconv.h and
            // CP_CertGetCertificateContextProperty
            //
            CRYPT_KEY_PROV_INFO *pKeyProvInfo = (CRYPT_KEY_PROV_INFO *)pvData;
            wwszContName = dup_wc2s_to_wc4s(pKeyProvInfo->pwszContainerName);
            wwszProvName = dup_wc2s_to_wc4s(pKeyProvInfo->pwszProvName);
            pKeyProvInfo->pwszContainerName = (wchar2_t *)wwszContName;
            pKeyProvInfo->pwszProvName      = (wchar2_t *)wwszProvName;
        }
        break;
    }
    default:
        break;
    }

    ret = pCertSetCertificateContextProperty(pCertContext,
                                             dwPropId,
                                             dwFlags,
                                             pvData);

    free(wwszContName);
    free(wwszProvName);

    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertAddCertificateContextToStore(HCERTSTORE hCertStore,
                                                PCCERT_CONTEXT pCertContext,
                                                DWORD dwAddDisposition,
                                                PCCERT_CONTEXT *ppStoreContext)
{
    BOOL ret;
    TRACE("\n");
    ret = pCertAddCertificateContextToStore(hCertStore,
                                            pCertContext,
                                            dwAddDisposition,
                                            ppStoreContext);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

BOOL WINAPI CP_CertFreeCertificateContext(PCCERT_CONTEXT pCertContext)
{
    BOOL ret = TRUE;
    TRACE("\n");
    if (pCertContext)
    {
        ret = pCertFreeCertificateContext(pCertContext);
        if (!ret) SetLastError(pGetLastError());
    }
    return ret;
}

BOOL WINAPI CP_CertGetCertificateChain(HCERTCHAINENGINE hChainEngine,
                                       PCCERT_CONTEXT pCertContext,
                                       LPFILETIME pTime,
                                       HCERTSTORE hAdditionalStore,
                                       PCERT_CHAIN_PARA pChainPara,
                                       DWORD dwFlags,
                                       LPVOID pvReserved,
                                       PCCERT_CHAIN_CONTEXT *ppChainContext)
{
    BOOL ret;
    TRACE("\n");
    ret = pCertGetCertificateChain(hChainEngine,
                                   pCertContext,
                                   pTime,
                                   hAdditionalStore,
                                   pChainPara,
                                   dwFlags,
                                   pvReserved,
                                   ppChainContext);
    if (!ret) SetLastError(pGetLastError());
    return ret;
}

VOID WINAPI CP_CertFreeCertificateChain(PCCERT_CHAIN_CONTEXT pChainContext)
{
    TRACE("\n");
    if (pChainContext)
    {
        pCertFreeCertificateChain(pChainContext);
    }
}
