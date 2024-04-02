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

// Windows
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
// Linux
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
// Wine
#include <wine/debug.h>

#include "proxy_util.h"

WINE_DEFAULT_DEBUG_CHANNEL(cpsspi_proxy);

#ifdef _WIN64
#define SONAME_LIBSSP "/opt/cprocsp/lib/amd64/libssp.so"
#else
#define SONAME_LIBSSP "/opt/cprocsp/lib/ia32/libssp.so"
#endif

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
// Windows WCHAR == wchar_t == uint16_t
// Linux   WCHAR == wchar_t == uint32_t
//
// Therefore, all Windows null-terminated Unicode strings in uint16_t*
// must be converted to uint32_t* using the dup_uint16_to_uint32 function
// and back using the conv_uint32_to_uint16 function.
//

typedef struct {
    uint32_t cbBuffer;
    uint64_t BufferType;
    void *pvBuffer;
} CP_SecBuffer;

typedef struct {
    uint64_t ulVersion;
    uint64_t cBuffers;
    CP_SecBuffer *pBuffers;
} CP_SecBufferDesc;

typedef struct
{
    uint64_t   cbHeader;
    uint64_t   cbTrailer;
    uint64_t   cbMaximumMessage;
    uint64_t   cBuffers;
    uint64_t   cbBlockSize;
} CP_SecPkgContext_StreamSizes;

static void Win2CP_SecBufferDesc(const SecBufferDesc *in,
                                 CP_SecBufferDesc *out);

static void CP2Win_SecBufferDesc(const CP_SecBufferDesc *in,
                                 SecBufferDesc *out);

static void CP2Win_SecPkgContext_StreamSizes(const CP_SecPkgContext_StreamSizes *in,
                                             SecPkgContext_StreamSizes *out);

static const char *SecPkgAttr2Str(ULONG ulAttribute);

//
// CryptoPro uses default calling convention on Linux
//

//
// SSPI
//

static PSecurityFunctionTableA (*pInitSecurityInterfaceA)();
static PSecurityFunctionTableW (*pInitSecurityInterfaceW)();

static SECURITY_STATUS (*pCPAcquireCredentialsHandleA)(
    char *pszPrincipal,
    char *pszPackage,
    unsigned long fCredentialUse,
    PLUID pvLogonID,
    PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    PVOID pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry
);

static SECURITY_STATUS (*pCPAcquireCredentialsHandleW)(
    uint32_t *pwszPrincipal,
    uint32_t *pwszPackage,
    unsigned long fCredentialUse,
    PLUID pvLogonID,
    PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    PVOID pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry
);

static SECURITY_STATUS (*pFreeCredentialsHandle)(
    PCredHandle phCredential
);

static SECURITY_STATUS (*pInitializeSecurityContextA)(
    PCredHandle phCredential,
    PCtxtHandle phContext,
    char *pszTargetName,
    unsigned long fContextReq,
    unsigned long Reserved1,
    unsigned long TargetDataRep,
    CP_SecBufferDesc *pInput,
    unsigned long Reserved2,
    PCtxtHandle phNewContext,
    CP_SecBufferDesc *pOutput,
    unsigned long *pfContextAttr,
    PTimeStamp ptsExpiry
);

static SECURITY_STATUS (*pInitializeSecurityContextW)(
    PCredHandle phCredential,
    PCtxtHandle phContext,
    uint32_t *pwszTargetName,
    unsigned long fContextReq,
    unsigned long Reserved1,
    unsigned long TargetDataRep,
    CP_SecBufferDesc *pInput,
    unsigned long Reserved2,
    PCtxtHandle phNewContext,
    CP_SecBufferDesc *pOutput,
    unsigned long *pfContextAttr,
    PTimeStamp ptsExpiry
);

static SECURITY_STATUS (*pDeleteSecurityContext)(
    PCtxtHandle phContext
);

static SECURITY_STATUS (*pQueryContextAttributesA)(
    PCtxtHandle phContext,
    unsigned long ulAttribute,
    PVOID pBuffer
);

// NB: QueryContextAttributesW is not exported

static SECURITY_STATUS (*pEncryptMessage)(
    PCtxtHandle phContext,
    unsigned long fQOP,
    CP_SecBufferDesc *pMessage,
    unsigned long MessageSeqNo
);

static SECURITY_STATUS (*pDecryptMessage)(
    PCtxtHandle phContext,
    CP_SecBufferDesc *pMessage,
    unsigned long MessageSeqNo,
    unsigned long *pfQOP
);

static SECURITY_STATUS (*pApplyControlToken)(
    PCtxtHandle phContext,
    CP_SecBufferDesc *pInput
);

static SECURITY_STATUS (*pFreeContextBuffer)(
    PVOID pvContextBuffer
);

static void *libssp;

static BOOL load_cpssp()
{
    if (!(libssp = dlopen(SONAME_LIBSSP, RTLD_NOW)))
    {
        FIXME("failed to load %s (%s)\n", SONAME_LIBSSP, dlerror());
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if ((p##f = dlsym(libssp, #f)) == NULL) \
    { \
        FIXME("%s not found in %s\n", #f, SONAME_LIBSSP); \
        libssp = NULL; \
        return FALSE; \
    }
    LOAD_FUNCPTR(InitSecurityInterfaceA);
    LOAD_FUNCPTR(InitSecurityInterfaceW);
    LOAD_FUNCPTR(CPAcquireCredentialsHandleA);
    LOAD_FUNCPTR(CPAcquireCredentialsHandleW);
    LOAD_FUNCPTR(FreeCredentialsHandle);
    LOAD_FUNCPTR(InitializeSecurityContextA);
    LOAD_FUNCPTR(InitializeSecurityContextW);
    LOAD_FUNCPTR(DeleteSecurityContext);
    LOAD_FUNCPTR(QueryContextAttributesA);
    LOAD_FUNCPTR(EncryptMessage);
    LOAD_FUNCPTR(DecryptMessage);
    LOAD_FUNCPTR(ApplyControlToken);
    LOAD_FUNCPTR(FreeContextBuffer);
#undef LOAD_FUNCPTR

    return TRUE;
}

static void unload_cpssp()
{
    dlclose(libssp);
    libssp = NULL;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        if (!load_cpssp()) return FALSE;
        DisableThreadLibraryCalls(hinst);
        break;

    case DLL_PROCESS_DETACH:
        unload_cpssp();
        break;
    }
    return TRUE;
}

SECURITY_STATUS WINAPI CP_AcquireCredentialsHandleA(
    CHAR *pszPrincipal,
    CHAR *pszPackage,
    ULONG fCredentialUse,
    PLUID pvLogonID,
    PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    PVOID pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;

    TRACE("\n");

    ret = pCPAcquireCredentialsHandleA(
        pszPrincipal,
        pszPackage,
        fCredentialUse,
        pvLogonID,
        pAuthData,
        pGetKeyFn,
        pvGetKeyArgument,
        phCredential,
        ptsExpiry);

    return ret;
}

SECURITY_STATUS WINAPI CP_AcquireCredentialsHandleW(
    WCHAR *pwszPrincipal,
    WCHAR *pwszPackage,
    ULONG fCredentialUse,
    PLUID pvLogonID,
    PVOID pAuthData,
    SEC_GET_KEY_FN pGetKeyFn,
    PVOID pvGetKeyArgument,
    PCredHandle phCredential,
    PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;

    TRACE("\n");

    //
    // pwszPrincipal and pwszPackage must be converted to uint32_t*.
    // See 'Convertion Notice' at the beginning of the file.
    //

    uint32_t *pwwszPrincipal = dup_uint16_to_uint32(pwszPrincipal);
    uint32_t *pwwszPackage   = dup_uint16_to_uint32(pwszPackage);

    ret = pCPAcquireCredentialsHandleW(
        pwwszPrincipal,
        pwwszPackage,
        fCredentialUse,
        pvLogonID,
        pAuthData,
        pGetKeyFn,
        pvGetKeyArgument,
        phCredential,
        ptsExpiry);

    free(pwwszPrincipal);
    free(pwwszPackage);

    return ret;
}

SECURITY_STATUS WINAPI CP_FreeCredentialsHandle(PCredHandle phCredential)
{
    SECURITY_STATUS ret;
    TRACE("\n");
    ret = pFreeCredentialsHandle(phCredential);
    return ret;
}

SECURITY_STATUS WINAPI CP_InitializeSecurityContextA(PCredHandle phCredential,
                                                     PCtxtHandle phContext,
                                                     CHAR *pszTargetName,
                                                     ULONG fContextReq,
                                                     ULONG Reserved1,
                                                     ULONG TargetDataRep,
                                                     PSecBufferDesc pInBufferDesc,
                                                     ULONG Reserved2,
                                                     PCtxtHandle phNewContext,
                                                     PSecBufferDesc pOutBufferDesc,
                                                     ULONG *pfContextAttr,
                                                     PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;
    TRACE("pszTargetName=%s\n", debugstr_a(pszTargetName));

    CP_SecBufferDesc *pCPInBufferDesc = NULL;
    CP_SecBuffer     *pCPInBuffers = NULL;

    CP_SecBufferDesc *pCPOutBufferDesc = NULL;
    CP_SecBuffer     *pCPOutBuffers = NULL;

    if (pInBufferDesc) {
        pCPInBufferDesc = malloc(sizeof(CP_SecBufferDesc));
        pCPInBuffers    = calloc(pInBufferDesc->cBuffers, sizeof(CP_SecBuffer));
        pCPInBufferDesc->pBuffers = pCPInBuffers;

        Win2CP_SecBufferDesc(pInBufferDesc, pCPInBufferDesc);
    }

    if (pOutBufferDesc) {
        pCPOutBufferDesc = malloc(sizeof(CP_SecBufferDesc));
        pCPOutBuffers    = calloc(pOutBufferDesc->cBuffers, sizeof(CP_SecBuffer));
        pCPOutBufferDesc->pBuffers = pCPOutBuffers;

        Win2CP_SecBufferDesc(pOutBufferDesc, pCPOutBufferDesc);
    }

    ret = pInitializeSecurityContextA(
        phCredential,
        phContext,
        pszTargetName,
        fContextReq,
        Reserved1,
        TargetDataRep,
        pCPInBufferDesc,
        Reserved2,
        phNewContext,
        pCPOutBufferDesc,
        (unsigned long *)pfContextAttr,
        ptsExpiry);

    if (pInBufferDesc) {
        CP2Win_SecBufferDesc(pCPInBufferDesc, pInBufferDesc);

        free(pCPInBuffers);
        free(pCPInBufferDesc);
    }

    if (pOutBufferDesc) {
        CP2Win_SecBufferDesc(pCPOutBufferDesc, pOutBufferDesc);

        free(pCPOutBuffers);
        free(pCPOutBufferDesc);
    }

    return ret;
}

SECURITY_STATUS WINAPI CP_InitializeSecurityContextW(PCredHandle phCredential,
                                                     PCtxtHandle phContext,
                                                     SEC_WCHAR *pwszTargetName,
                                                     ULONG fContextReq,
                                                     ULONG Reserved1,
                                                     ULONG TargetDataRep,
                                                     PSecBufferDesc pInBufferDesc,
                                                     ULONG Reserved2,
                                                     PCtxtHandle phNewContext,
                                                     PSecBufferDesc pOutBufferDesc,
                                                     ULONG *pfContextAttr,
                                                     PTimeStamp ptsExpiry)
{
    SECURITY_STATUS ret;
    TRACE("pwszTargetName=%s\n", debugstr_w(pwszTargetName));

    //
    // pwszTargetName must be converted to uint32_t*.
    // See 'Convertion Notice' at the beginning of the file.
    // But easier to fallback to CP_InitializeSecurityContextA.
    //

    LPSTR pszTargetName = NULL;
    if (pwszTargetName)
    {
        size_t lenW = lstrlenW(pwszTargetName) + 1;
        size_t len = WideCharToMultiByte(CP_UTF8, 0, pwszTargetName, lenW, NULL, 0, NULL, NULL);
        pszTargetName = malloc(len);
        WideCharToMultiByte(CP_UTF8, 0, pwszTargetName, lenW, pszTargetName, len, NULL, NULL);
    }

    ret = CP_InitializeSecurityContextA(
        phCredential,
        phContext,
        pszTargetName,
        fContextReq,
        Reserved1,
        TargetDataRep,
        pInBufferDesc,
        Reserved2,
        phNewContext,
        pOutBufferDesc,
        pfContextAttr,
        ptsExpiry);

    free(pszTargetName);

    return ret;
}

SECURITY_STATUS WINAPI CP_DeleteSecurityContext(PCtxtHandle phContext)
{
    SECURITY_STATUS ret;
    TRACE("\n");
    ret = pDeleteSecurityContext(phContext);
    return ret;
}

SECURITY_STATUS WINAPI CP_QueryContextAttributes(PCtxtHandle phContext,
                                                 ULONG ulAttribute,
                                                 PVOID pBuffer)
{
    SECURITY_STATUS ret;
    VOID *pCPBuffer = NULL;

    TRACE("ulAttribute=%s\n", SecPkgAttr2Str(ulAttribute));

    switch (ulAttribute) {
    case SECPKG_ATTR_STREAM_SIZES:
        pCPBuffer = malloc(sizeof(CP_SecPkgContext_StreamSizes));
        break;

    case SECPKG_ATTR_CONNECTION_INFO:
    case SECPKG_ATTR_ISSUER_LIST_EX:
    case SECPKG_ATTR_REMOTE_CERT_CONTEXT:
        pCPBuffer = pBuffer;
        break;

    default:
        FIXME("not implemented ulAttribute=%u\n", ulAttribute);
        return SEC_E_SECPKG_NOT_FOUND;
    }

    ret = pQueryContextAttributesA(phContext, ulAttribute, pCPBuffer);

    switch (ulAttribute) {
    case SECPKG_ATTR_STREAM_SIZES:
        if (ret == SEC_E_OK) {
            CP2Win_SecPkgContext_StreamSizes(pCPBuffer, pBuffer);
        }
        break;

    case SECPKG_ATTR_CONNECTION_INFO:
    case SECPKG_ATTR_ISSUER_LIST_EX:
    case SECPKG_ATTR_REMOTE_CERT_CONTEXT:
        pBuffer = pCPBuffer;
        pCPBuffer = NULL;
        break;

    default:
        FIXME("not implemented ulAttribute=%u\n", ulAttribute);
        return SEC_E_SECPKG_NOT_FOUND;
    }

    free(pCPBuffer);
    return ret;
}

SECURITY_STATUS WINAPI CP_EncryptMessage(PCtxtHandle phContext,
                                         ULONG fQOP,
                                         SecBufferDesc *pBufferDesc,
                                         ULONG MessageSeqNo)
{
    TRACE("\n");

    SECURITY_STATUS ret;

    CP_SecBufferDesc *pCPBufferDesc = NULL;
    CP_SecBuffer     *pCPBuffers = NULL;

    if (pBufferDesc) {
        pCPBufferDesc = malloc(sizeof(CP_SecBufferDesc));
        pCPBuffers    = calloc(pBufferDesc->cBuffers, sizeof(CP_SecBuffer));
        pCPBufferDesc->pBuffers = pCPBuffers;

        Win2CP_SecBufferDesc(pBufferDesc, pCPBufferDesc);
    }

    ret = pEncryptMessage(phContext, fQOP, pCPBufferDesc, MessageSeqNo);

    if (pBufferDesc) {
        CP2Win_SecBufferDesc(pCPBufferDesc, pBufferDesc);

        free(pCPBuffers);
        free(pCPBufferDesc);
    }

    return ret;
}

SECURITY_STATUS WINAPI CP_DecryptMessage(PCtxtHandle phContext,
                                         SecBufferDesc *pBufferDesc,
                                         ULONG MessageSeqNo,
                                         ULONG *pfQOP)
{
    TRACE("\n");

    SECURITY_STATUS ret;

    CP_SecBufferDesc *pCPBufferDesc = NULL;
    CP_SecBuffer     *pCPBuffers = NULL;

    if (pBufferDesc) {
        pCPBufferDesc = malloc(sizeof(CP_SecBufferDesc));
        pCPBuffers    = calloc(pBufferDesc->cBuffers, sizeof(CP_SecBuffer));
        pCPBufferDesc->pBuffers = pCPBuffers;

        Win2CP_SecBufferDesc(pBufferDesc, pCPBufferDesc);
    }

    ret = pDecryptMessage(phContext,
                          pCPBufferDesc,
                          MessageSeqNo,
                          (unsigned long *)pfQOP);

    if (pBufferDesc) {
        CP2Win_SecBufferDesc(pCPBufferDesc, pBufferDesc);

        free(pCPBuffers);
        free(pCPBufferDesc);
    }

    return ret;
}

SECURITY_STATUS WINAPI CP_ApplyControlToken(PCtxtHandle phContext,
                                            SecBufferDesc *pBufferDesc)
{
    TRACE("\n");

    SECURITY_STATUS ret;

    CP_SecBufferDesc *pCPBufferDesc = NULL;
    CP_SecBuffer     *pCPBuffers = NULL;

    if (pBufferDesc) {
        pCPBufferDesc = malloc(sizeof(CP_SecBufferDesc));
        pCPBuffers    = calloc(pBufferDesc->cBuffers, sizeof(CP_SecBuffer));
        pCPBufferDesc->pBuffers = pCPBuffers;

        Win2CP_SecBufferDesc(pBufferDesc, pCPBufferDesc);
    }

    ret = pApplyControlToken(phContext, pCPBufferDesc);

    if (pBufferDesc) {
        CP2Win_SecBufferDesc(pCPBufferDesc, pBufferDesc);

        free(pCPBuffers);
        free(pCPBufferDesc);
    }

    return ret;
}

SECURITY_STATUS WINAPI CP_FreeContextBuffer(PVOID pvContextBuffer)
{
    SECURITY_STATUS ret;
    TRACE("\n");
    ret = pFreeContextBuffer(pvContextBuffer);
    return ret;
}

static SecurityFunctionTableA securityFunctionTableA = {
    SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION,
    NULL, //EnumerateSecurityPackagesA,
    NULL, //QueryCredentialsAttributesA,
    CP_AcquireCredentialsHandleA,
    CP_FreeCredentialsHandle,
    NULL, /* Reserved2 */
    CP_InitializeSecurityContextA,
    NULL, //AcceptSecurityContext,
    NULL, //CompleteAuthToken,
    CP_DeleteSecurityContext,
    CP_ApplyControlToken,
    CP_QueryContextAttributes,
    NULL, //ImpersonateSecurityContext,
    NULL, //RevertSecurityContext,
    NULL, //MakeSignature,
    NULL, //VerifySignature,
    CP_FreeContextBuffer,
    NULL, //QuerySecurityPackageInfoA,
    NULL, /* Reserved3 */
    NULL, /* Reserved4 */
    NULL, //ExportSecurityContext,
    NULL, //ImportSecurityContextA,
    NULL, //AddCredentialsA,
    NULL, /* Reserved8 */
    NULL, //QuerySecurityContextToken,
    CP_EncryptMessage,
    CP_DecryptMessage,
    NULL, //SetContextAttributesA
};

static SecurityFunctionTableW securityFunctionTableW = {
    SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION,
    NULL, //EnumerateSecurityPackagesW,
    NULL, //QueryCredentialsAttributesW,
    CP_AcquireCredentialsHandleW,
    CP_FreeCredentialsHandle,
    NULL, /* Reserved2 */
    CP_InitializeSecurityContextW,
    NULL, //AcceptSecurityContext,
    NULL, //CompleteAuthToken,
    CP_DeleteSecurityContext,
    CP_ApplyControlToken,
    CP_QueryContextAttributes,
    NULL, //ImpersonateSecurityContext,
    NULL, //RevertSecurityContext,
    NULL, //MakeSignature,
    NULL, //VerifySignature,
    CP_FreeContextBuffer,
    NULL, //QuerySecurityPackageInfoW,
    NULL, /* Reserved3 */
    NULL, /* Reserved4 */
    NULL, //ExportSecurityContext,
    NULL, //ImportSecurityContextW,
    NULL, //AddCredentialsW,
    NULL, /* Reserved8 */
    NULL, //QuerySecurityContextToken,
    CP_EncryptMessage,
    CP_DecryptMessage,
    NULL, //SetContextAttributesW
};

PSecurityFunctionTableA WINAPI InitSecurityInterfaceA()
{
    return &securityFunctionTableA;
}

PSecurityFunctionTableW WINAPI InitSecurityInterfaceW()
{
    return &securityFunctionTableW;
}

static void Win2CP_SecBufferDesc(const SecBufferDesc *in,
                                 CP_SecBufferDesc *out)
{
    out->ulVersion = in->ulVersion;
    out->cBuffers  = in->cBuffers;

    for (size_t i = 0; i < in->cBuffers; ++i) {
        out->pBuffers[i].cbBuffer   = in->pBuffers[i].cbBuffer;
        out->pBuffers[i].BufferType = in->pBuffers[i].BufferType;
        out->pBuffers[i].pvBuffer   = in->pBuffers[i].pvBuffer;
    }
}

static void CP2Win_SecBufferDesc(const CP_SecBufferDesc *in,
                                 SecBufferDesc *out)
{
    out->ulVersion = in->ulVersion;
    out->cBuffers  = in->cBuffers;

    for (size_t i = 0; i < in->cBuffers; ++i) {
        out->pBuffers[i].cbBuffer   = in->pBuffers[i].cbBuffer;
        out->pBuffers[i].BufferType = in->pBuffers[i].BufferType;
        out->pBuffers[i].pvBuffer   = in->pBuffers[i].pvBuffer;
    }
}

static void CP2Win_SecPkgContext_StreamSizes(const CP_SecPkgContext_StreamSizes *in,
                                             SecPkgContext_StreamSizes *out)
{
    out->cbHeader         = in->cbHeader;
    out->cbTrailer        = in->cbTrailer;
    out->cbMaximumMessage = in->cbMaximumMessage;
    out->cBuffers         = in->cBuffers;
    out->cbBlockSize      = in->cbBlockSize;
}

static const char *SecPkgAttr2Str(ULONG ulAttribute)
{
    switch (ulAttribute) {
    case SECPKG_ATTR_STREAM_SIZES:
        return "SECPKG_ATTR_STREAM_SIZES";
    case SECPKG_ATTR_CONNECTION_INFO:
        return "SECPKG_ATTR_CONNECTION_INFO";
    case SECPKG_ATTR_ISSUER_LIST_EX:
        return "SECPKG_ATTR_ISSUER_LIST_EX";
    case SECPKG_ATTR_REMOTE_CERT_CONTEXT:
        return "SECPKG_ATTR_REMOTE_CERT_CONTEXT";
    default:
        return "UNKNOWN";
    }
}
