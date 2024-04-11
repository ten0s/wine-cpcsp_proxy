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

#include <stdio.h>

#define CP_CAPI_SPEC
#include "cpcapi.h"

#define CP_CAPI_PROXY_DLL "cpcapi_proxy.dll.so"

static HMODULE g_hCAPI = NULL;

BOOL CP_CAPI_Init()
{
    g_hCAPI = LoadLibraryA(CP_CAPI_PROXY_DLL);
    if (g_hCAPI == NULL)
    {
        fprintf(stderr, "LoadLibrary(%s) failed 0x%x\n",
                CP_CAPI_PROXY_DLL, GetLastError());
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    f = (f##_t)GetProcAddress(g_hCAPI, #f);                        \
    if (f == NULL)                                                 \
    {                                                              \
        fprintf(stderr, "GetProcAddress(..., %s) failed 0x%x\n",   \
                #f, GetLastError());                               \
        return FALSE;                                              \
    }

    //
    // CAPI10
    //
    LOAD_FUNCPTR(CP_CryptAcquireContextA);
    LOAD_FUNCPTR(CP_CryptAcquireContextW);
    LOAD_FUNCPTR(CP_CryptGetProvParam);
    LOAD_FUNCPTR(CP_CryptSetProvParam);
    LOAD_FUNCPTR(CP_CryptGetUserKey);
    LOAD_FUNCPTR(CP_CryptDestroyKey);
    LOAD_FUNCPTR(CP_CryptReleaseContext);

    //
    // CAPI20
    //
    LOAD_FUNCPTR(CP_CryptAcquireCertificatePrivateKey);
    LOAD_FUNCPTR(CP_CryptEncodeObjectEx);
    LOAD_FUNCPTR(CP_CryptDecodeObjectEx);
    LOAD_FUNCPTR(CP_CryptExportPublicKeyInfo);
    LOAD_FUNCPTR(CP_CertComparePublicKeyInfo);
    LOAD_FUNCPTR(CP_CertOpenStore);
    LOAD_FUNCPTR(CP_CertOpenSystemStoreA);
    LOAD_FUNCPTR(CP_CertOpenSystemStoreW);
    LOAD_FUNCPTR(CP_CertCloseStore);
    LOAD_FUNCPTR(CP_CertEnumCertificatesInStore);
    LOAD_FUNCPTR(CP_CertFindCertificateInStore);
    LOAD_FUNCPTR(CP_CertDeleteCertificateFromStore);
    LOAD_FUNCPTR(CP_CertGetIssuerCertificateFromStore);
    LOAD_FUNCPTR(CP_CertCreateCertificateContext);
    LOAD_FUNCPTR(CP_CertDuplicateCertificateContext);
    LOAD_FUNCPTR(CP_CertGetCertificateContextProperty);
    LOAD_FUNCPTR(CP_CertSetCertificateContextProperty);
    LOAD_FUNCPTR(CP_CertAddCertificateContextToStore);
    LOAD_FUNCPTR(CP_CertFreeCertificateContext);
    LOAD_FUNCPTR(CP_CertGetCertificateChain);
    LOAD_FUNCPTR(CP_CertFreeCertificateChain);

#undef LOAD_FUNCPTR

    return TRUE;
}

void CP_CAPI_Deinit()
{
    FreeLibrary(g_hCAPI);
    g_hCAPI = NULL;
}
