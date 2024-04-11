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

#ifndef __CP_CAPI_H__
#define __CP_CAPI_H__

#include <windows.h>
#include <wincrypt.h>

#ifndef CP_CAPI_SPEC
    #define CP_CAPI_SPEC extern
#endif

typedef BOOL (__stdcall *CP_CryptAcquireContextA_t)(
    HCRYPTPROV *phProv,
    LPCSTR szContName,
    LPCSTR szProvName,
    DWORD dwProvType,
    DWORD dwFlags
);
CP_CAPI_SPEC CP_CryptAcquireContextA_t CP_CryptAcquireContextA;

typedef BOOL (__stdcall *CP_CryptAcquireContextW_t)(
    HCRYPTPROV *phProv,
    LPCWSTR wszContName,
    LPCWSTR wszProvName,
    DWORD dwProvType,
    DWORD dwFlags
);
CP_CAPI_SPEC CP_CryptAcquireContextW_t CP_CryptAcquireContextW;

typedef BOOL (__stdcall *CP_CryptGetProvParam_t)(
    HCRYPTPROV hProv,
    DWORD dwParam,
    BYTE *pbData,
    DWORD *pdwDataLen,
    DWORD dwFlags
);
CP_CAPI_SPEC CP_CryptGetProvParam_t CP_CryptGetProvParam;

typedef BOOL (__stdcall *CP_CryptSetProvParam_t)(
    HCRYPTPROV hProv,
    DWORD dwParam,
    const BYTE *pbData,
    DWORD dwFlags
);
CP_CAPI_SPEC CP_CryptSetProvParam_t CP_CryptSetProvParam;

typedef BOOL (__stdcall *CP_CryptGetUserKey_t)(
    HCRYPTPROV hProv,
    DWORD dwKeySpec,
    HCRYPTKEY *phUserKey
);
CP_CAPI_SPEC CP_CryptGetUserKey_t CP_CryptGetUserKey;

typedef BOOL (__stdcall *CP_CryptDestroyKey_t)(
    HCRYPTKEY hKey
);
CP_CAPI_SPEC CP_CryptDestroyKey_t CP_CryptDestroyKey;

typedef BOOL (__stdcall *CP_CryptReleaseContext_t)(
    HCRYPTPROV hProv,
    DWORD dwFlags
);
CP_CAPI_SPEC CP_CryptReleaseContext_t CP_CryptReleaseContext;

// CAPI20

typedef BOOL (__stdcall *CP_CryptAcquireCertificatePrivateKey_t)(
    PCCERT_CONTEXT pCert,
    DWORD dwFlags,
    void *pvReserved,
    HCRYPTPROV *phCryptProv,
    DWORD *pdwKeySpec,
    BOOL *pfCallerFreeProv
);
CP_CAPI_SPEC CP_CryptAcquireCertificatePrivateKey_t CP_CryptAcquireCertificatePrivateKey;

typedef BOOL (__stdcall *CP_CryptEncodeObjectEx_t)(
    DWORD dwCertEncodingType,
    LPCSTR lpszStructType,
    const void *pvStructInfo,
    DWORD dwFlags,
    PCRYPT_ENCODE_PARA pEncodePara,
    void *pvEncoded,
    DWORD *pcbEncoded
);
CP_CAPI_SPEC CP_CryptEncodeObjectEx_t CP_CryptEncodeObjectEx;

typedef BOOL (__stdcall *CP_CryptDecodeObjectEx_t)(
    DWORD dwCertEncodingType,
    LPCSTR lpszStructType,
    const BYTE *pbEncoded,
    DWORD cbEncoded,
    DWORD dwFlags,
    PCRYPT_DECODE_PARA pDecodePara,
    void *pvStructInfo,
    DWORD *pcbStructInfo
);
CP_CAPI_SPEC CP_CryptDecodeObjectEx_t CP_CryptDecodeObjectEx;

typedef BOOL (__stdcall *CP_CryptExportPublicKeyInfo_t)(
    HCRYPTPROV hProv,
    DWORD dwKeySpec,
    DWORD dwCertEncodingType,
    PCERT_PUBLIC_KEY_INFO pInfo,
    DWORD *pcbInfo
);
CP_CAPI_SPEC CP_CryptExportPublicKeyInfo_t CP_CryptExportPublicKeyInfo;

typedef BOOL (__stdcall *CP_CertComparePublicKeyInfo_t)(
    DWORD dwCertEncodingType,
    PCERT_PUBLIC_KEY_INFO pPublicKey1,
    PCERT_PUBLIC_KEY_INFO pPublicKey2
);
CP_CAPI_SPEC CP_CertComparePublicKeyInfo_t CP_CertComparePublicKeyInfo;

typedef HCERTSTORE (__stdcall *CP_CertOpenStore_t)(
    LPCSTR lpszStoreProvider,
    DWORD dwEncodingType,
    HCRYPTPROV hCryptProv,
    DWORD dwFlags,
    const void *pvPara
);
CP_CAPI_SPEC CP_CertOpenStore_t CP_CertOpenStore;

typedef HCERTSTORE (__stdcall *CP_CertOpenSystemStoreA_t)(
    HCRYPTPROV hProv,
    LPCSTR szSubsystemProtocol
);
CP_CAPI_SPEC CP_CertOpenSystemStoreA_t CP_CertOpenSystemStoreA;

typedef HCERTSTORE (__stdcall *CP_CertOpenSystemStoreW_t)(
    HCRYPTPROV hProv,
    LPCWSTR wszSubsystemProtocol
);
CP_CAPI_SPEC CP_CertOpenSystemStoreW_t CP_CertOpenSystemStoreW;

typedef BOOL (__stdcall *CP_CertCloseStore_t)(
    HCERTSTORE hCertStore,
    DWORD dwFlags
);
CP_CAPI_SPEC CP_CertCloseStore_t CP_CertCloseStore;

typedef PCCERT_CONTEXT (__stdcall *CP_CertEnumCertificatesInStore_t)(
    HCERTSTORE hCertStore,
    PCCERT_CONTEXT pPrevCertContext
);
CP_CAPI_SPEC CP_CertEnumCertificatesInStore_t CP_CertEnumCertificatesInStore;

typedef PCCERT_CONTEXT (__stdcall *CP_CertFindCertificateInStore_t)(
    HCERTSTORE hCertStore,
    DWORD dwCertEncodingType,
    DWORD dwFindFlags,
    DWORD dwFindType,
    const void *pvFindPara,
    PCCERT_CONTEXT pPrevCertContext
);
CP_CAPI_SPEC CP_CertFindCertificateInStore_t CP_CertFindCertificateInStore;

typedef BOOL (__stdcall *CP_CertDeleteCertificateFromStore_t)(
    PCCERT_CONTEXT pCertContext
);
CP_CAPI_SPEC CP_CertDeleteCertificateFromStore_t CP_CertDeleteCertificateFromStore;

typedef PCCERT_CONTEXT (__stdcall *CP_CertGetIssuerCertificateFromStore_t)(
    HCERTSTORE hCertStore,
    PCCERT_CONTEXT pSubjectContext,
    PCCERT_CONTEXT pPrevIssuerContext,
    DWORD *pdwFlags
);
CP_CAPI_SPEC CP_CertGetIssuerCertificateFromStore_t CP_CertGetIssuerCertificateFromStore;

typedef PCCERT_CONTEXT (__stdcall *CP_CertCreateCertificateContext_t)(
    DWORD dwCertEncodingType,
    const BYTE *pbCertEncoded,
    DWORD cbCertEncoded
);
CP_CAPI_SPEC CP_CertCreateCertificateContext_t CP_CertCreateCertificateContext;

typedef PCCERT_CONTEXT (__stdcall *CP_CertDuplicateCertificateContext_t)(
    PCCERT_CONTEXT pCertContext
);
CP_CAPI_SPEC CP_CertDuplicateCertificateContext_t CP_CertDuplicateCertificateContext;

typedef BOOL (__stdcall *CP_CertGetCertificateContextProperty_t)(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId,
    void *pvData,
    DWORD *pcbData
);
CP_CAPI_SPEC CP_CertGetCertificateContextProperty_t CP_CertGetCertificateContextProperty;

typedef BOOL (__stdcall *CP_CertSetCertificateContextProperty_t)(
    PCCERT_CONTEXT pCertContext,
    DWORD dwPropId,
    DWORD dwFlags,
    const void *pvData
);
CP_CAPI_SPEC CP_CertSetCertificateContextProperty_t CP_CertSetCertificateContextProperty;

typedef BOOL (__stdcall *CP_CertAddCertificateContextToStore_t)(
    HCERTSTORE hCertStore,
    PCCERT_CONTEXT pCertContext,
    DWORD dwAddDisposition,
    PCCERT_CONTEXT *ppStoreContext
);
CP_CAPI_SPEC CP_CertAddCertificateContextToStore_t CP_CertAddCertificateContextToStore;

typedef BOOL (__stdcall *CP_CertFreeCertificateContext_t)(
    PCCERT_CONTEXT pCertContext
);
CP_CAPI_SPEC CP_CertFreeCertificateContext_t CP_CertFreeCertificateContext;

typedef BOOL (__stdcall *CP_CertGetCertificateChain_t)(
    HCERTCHAINENGINE hChainEngine,
    PCCERT_CONTEXT pCertContext,
    LPFILETIME pTime,
    HCERTSTORE hAdditionalStore,
    PCERT_CHAIN_PARA pChainPara,
    DWORD dwFlags,
    LPVOID pvReserved,
    PCCERT_CHAIN_CONTEXT *ppChainContext
);
CP_CAPI_SPEC CP_CertGetCertificateChain_t CP_CertGetCertificateChain;

typedef VOID (__stdcall *CP_CertFreeCertificateChain_t)(
    PCCERT_CHAIN_CONTEXT pChainContext
);
CP_CAPI_SPEC CP_CertFreeCertificateChain_t CP_CertFreeCertificateChain;

BOOL CP_CAPI_Init();
void CP_CAPI_Deinit();

#endif // __CP_CAPI_H__
