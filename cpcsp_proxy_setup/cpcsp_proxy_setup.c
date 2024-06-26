/*
 * Copyright (C) 2019 Dmitry Timoshkov for Etersoft
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

#define WIN32_LEAN_AND_MEAN

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define NONAMELESSUNION
#include <windows.h>
#include <wincrypt.h>

#include <wine/debug.h>

#include "print_id_name.h"

#ifdef _WIN64
#define SONAME_LIBCAPI10 "/opt/cprocsp/lib/amd64/libcapi10.so"
#define SONAME_LIBCAPI20 "/opt/cprocsp/lib/amd64/libcapi20.so"
#else
#define SONAME_LIBCAPI10 "/opt/cprocsp/lib/ia32/libcapi10.so"
#define SONAME_LIBCAPI20 "/opt/cprocsp/lib/ia32/libcapi20.so"
#endif

static const char proxy_dll[] = "cpcsp_proxy.dll.so";

/* CryptoPro uses default calling convention under linux */
static DWORD (*pCertEnumCertificateContextProperties)(PCCERT_CONTEXT,DWORD);
static PCCERT_CONTEXT (*pCertEnumCertificatesInStore)(HCERTSTORE,PCCERT_CONTEXT);
static BOOL (*pCertGetCertificateContextProperty)(PCCERT_CONTEXT,DWORD,void *,DWORD *);
static DWORD (*pCertGetNameStringA)(PCCERT_CONTEXT,DWORD,DWORD,void *,LPSTR,DWORD);
static HCERTSTORE (*pCertOpenStore)(LPCSTR,DWORD,HCRYPTPROV_LEGACY,DWORD,const void *);
static BOOL (*pCertCloseStore)(HCERTSTORE,DWORD);
static BOOL (*pCertControlStore)(HCERTSTORE,DWORD,DWORD,void const *);
static BOOL (*pCryptEnumProvidersA)(DWORD,DWORD *,DWORD,DWORD *,LPSTR,DWORD *);
static BOOL (*pCryptEnumOIDInfo)(DWORD,DWORD,void *,PFN_CRYPT_ENUM_OID_INFO);
static BOOL (*pGetLastError)(void);

static BOOL verbose = FALSE;

static BOOL load_cpcsp(void)
{
    void *libcapi10, *libcapi20;

    if (!(libcapi10 = dlopen(SONAME_LIBCAPI10, RTLD_NOW)))
    {
        printf("failed to load %s (%s)\n", SONAME_LIBCAPI10, dlerror());
        return FALSE;
    }

    if (!(libcapi20 = dlopen(SONAME_LIBCAPI20, RTLD_NOW)))
    {
        printf("failed to load %s (%s)\n", SONAME_LIBCAPI20, dlerror());
        return FALSE;
    }

#define LOAD_FUNCPTR(f) \
    if ((p##f = dlsym(libcapi20, #f)) == NULL) \
    { \
        printf("%s not found in %s\n", #f, SONAME_LIBCAPI20); \
        return FALSE; \
    }
    LOAD_FUNCPTR(CertEnumCertificateContextProperties);
    LOAD_FUNCPTR(CertEnumCertificatesInStore);
    LOAD_FUNCPTR(CertGetCertificateContextProperty);
    LOAD_FUNCPTR(CertGetNameStringA);
    LOAD_FUNCPTR(CertOpenStore);
    LOAD_FUNCPTR(CertCloseStore);
    LOAD_FUNCPTR(CertControlStore);
    LOAD_FUNCPTR(CryptEnumOIDInfo);
    LOAD_FUNCPTR(GetLastError);
#undef LOAD_FUNCPTR

#define LOAD_FUNCPTR(f) \
    if ((p##f = dlsym(libcapi10, #f)) == NULL) \
    { \
        printf("%s not found in %s\n", #f, SONAME_LIBCAPI10); \
        return FALSE; \
    }
    LOAD_FUNCPTR(CryptEnumProvidersA);
#undef LOAD_FUNCPTR

    return TRUE;
}

struct prop_info
{
    DWORD id;
    CRYPT_DATA_BLOB data;
};

struct cert_info
{
    DWORD dwCertEncodingType;
    CRYPT_DATA_BLOB data;
    DWORD prop_count;
    struct prop_info *prop;
    WCHAR *subject;
};

struct store_info
{
    DWORD cert_count;
    struct cert_info *cert;
};

static void *xmalloc(size_t size)
{
    void *res;
    res = malloc(size ? size : 1);
    if (res == NULL)
    {
        printf("Virtual memory exhausted\n");
        exit(-1);
    }
    return res;
}

static void *xrealloc(void *ptr, size_t size)
{
    void *res = realloc(ptr, size);
    if (size && res == NULL)
    {
        printf("Virtual memory exhausted\n");
        exit(-1);
    }
    return res;
}

static void *xmemdup(const void *ptr, size_t size)
{
    void *res = xmalloc(size);
    memcpy(res, ptr, size);
    return res;
}

static WCHAR *xstrdupW(const WCHAR *str)
{
    return xmemdup(str, (lstrlenW(str) + 1) * sizeof(WCHAR));
}

static const char *unix_cp(const char *buf)
{
    UINT in_cp;
    WCHAR in[512];
    static char out[512];

    in_cp = GetACP();
    if (in_cp == 1252) in_cp = 1251;

    MultiByteToWideChar(in_cp, 0, buf, -1, in, ARRAY_SIZE(in));
    WideCharToMultiByte(CP_UTF8, 0, in, -1, out, sizeof(out), NULL, NULL);
    out[sizeof(out) - 1] = 0;

    return out;
}

static void print_cert_info(PCCERT_CONTEXT ctx)
{
    char buf[512];
    SYSTEMTIME st;
    DWORD propid, size;

    printf("dwEncodingType: %#08x\n", ctx->dwCertEncodingType);
    printf("cbCertEncoded: %u bytes\n", ctx->cbCertEncoded);

    if (!pCertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0, NULL, buf, sizeof(buf)))
    {
        printf("CertGetNameString error %#x\n", pGetLastError());
        return;
    }
    printf("Subject: %s\n", unix_cp(buf));

    if (!pCertGetNameStringA(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            CERT_NAME_ISSUER_FLAG, NULL, buf, sizeof(buf)))
    {
        printf("CertGetNameString error %#x\n", pGetLastError());
        return;
    }
    printf("Issuer: %s\n", unix_cp(buf));

    FileTimeToSystemTime(&ctx->pCertInfo->NotBefore, &st);
    printf("Not valid before: %d.%02d.%04d %02d:%02d:%02d\n",
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);

    FileTimeToSystemTime(&ctx->pCertInfo->NotAfter, &st);
    printf("Not valid after: %d.%02d.%04d %02d:%02d:%02d\n",
           st.wDay, st.wMonth, st.wYear, st.wHour, st.wMinute, st.wSecond);

    propid = 0;
    for (;;)
    {
        propid = pCertEnumCertificateContextProperties(ctx, propid);
        if (!propid) break;
        if (!pCertGetCertificateContextProperty(ctx, propid, NULL, &size))
        {
            printf("CertGetCertificateContextProperty error %#x\n", pGetLastError());
            continue;
        }
        printf("propid: %u (%s), size %u bytes\n", propid, propid_to_name(propid), size);
    }
}

static void wchar4_to_wchar2(const int *in, WCHAR *out)
{
    while (*in) *out++ = *in++;
    *out = 0;
}

static void provinfo_to_win32(CRYPT_KEY_PROV_INFO *info, size_t size)
{
    CRYPT_KEY_PROV_INFO *tmp = xmemdup(info, size);

    wchar4_to_wchar2((const int *)tmp->pwszContainerName, info->pwszContainerName);
    wchar4_to_wchar2((const int *)tmp->pwszProvName, info->pwszProvName);

    free(tmp);
}

static BOOL read_prop_info(PCCERT_CONTEXT ctx, struct cert_info *cert)
{
    DWORD propid;

    cert->prop_count = 0;

    propid = 0;
    for (;;)
    {
        propid = pCertEnumCertificateContextProperties(ctx, propid);
        if (!propid) break;

        if (!cert->prop_count)
            cert->prop = xmalloc(sizeof(cert->prop[0]));
        else
            cert->prop = xrealloc(cert->prop, (cert->prop_count + 1) * sizeof(cert->prop[0]));

        cert->prop[cert->prop_count].id = propid;

        if (!pCertGetCertificateContextProperty(ctx, propid, NULL, &cert->prop[cert->prop_count].data.cbData))
        {
            printf("CertGetCertificateContextProperty error %#x\n", pGetLastError());
            return FALSE;
        }

        cert->prop[cert->prop_count].data.pbData = xmalloc(cert->prop[cert->prop_count].data.cbData);
        if (!pCertGetCertificateContextProperty(ctx, propid, cert->prop[cert->prop_count].data.pbData, &cert->prop[cert->prop_count].data.cbData))
        {
            printf("CertGetCertificateContextProperty error %#x\n", pGetLastError());
            return FALSE;
        }

        if (propid == CERT_KEY_PROV_INFO_PROP_ID)
        {
            CRYPT_KEY_PROV_INFO *pinfo = (CRYPT_KEY_PROV_INFO *)cert->prop[cert->prop_count].data.pbData;

            provinfo_to_win32(pinfo, cert->prop[cert->prop_count].data.cbData);

            if (verbose)
                printf("CERT_KEY_PROV_INFO_PROP_ID: %s, %s, type %u, flags %#x, params: %u,%p, keyspec %#x\n",
                      debugstr_w(pinfo->pwszContainerName), debugstr_w(pinfo->pwszProvName), pinfo->dwProvType,
                      pinfo->dwFlags, pinfo->cProvParam, pinfo->rgProvParam, pinfo->dwKeySpec);
        }

        cert->prop_count++;
    }

    return TRUE;
}


static BOOL read_store_info(const char *store_name, struct store_info *store)
{
    HCERTSTORE hstore;
    PCCERT_CONTEXT ctx;

    printf("Reading certificates from %s store\n", store_name);

    store->cert_count = 0;

    hstore = pCertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                            CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, store_name);
    if (!hstore)
    {
        printf("CertOpenStore(%s) error %#x\n", store_name, pGetLastError());
        return FALSE;
    }

    ctx = NULL;
    while ((ctx = pCertEnumCertificatesInStore(hstore, ctx)))
    {
        WCHAR buf[512];

        print_cert_info(ctx);

        if (!store->cert_count)
            store->cert = xmalloc(sizeof(store->cert[0]));
        else
            store->cert = xrealloc(store->cert, (store->cert_count + 1) * sizeof(store->cert[0]));

        store->cert[store->cert_count].dwCertEncodingType = ctx->dwCertEncodingType;
        store->cert[store->cert_count].data.cbData = ctx->cbCertEncoded;
        store->cert[store->cert_count].data.pbData = xmemdup(ctx->pbCertEncoded, ctx->cbCertEncoded);

        if (!read_prop_info(ctx, &store->cert[store->cert_count]))
            return FALSE;

        if (CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                               0, NULL, buf, ARRAY_SIZE(buf)))
            store->cert[store->cert_count].subject = xstrdupW(buf);

        store->cert_count++;
        printf("\n");
    }

    pCertCloseStore(hstore, 0);
    return TRUE;
}

static BOOL save_prop_info(PCCERT_CONTEXT ctx, struct cert_info *cert)
{
    DWORD i;

    for (i = 0; i < cert->prop_count; i++)
    {
        switch (cert->prop[i].id)
        {
        case CERT_KEY_PROV_INFO_PROP_ID:
        {
            CRYPT_KEY_PROV_INFO *pinfo = (CRYPT_KEY_PROV_INFO *)cert->prop[i].data.pbData;

            if (verbose)
                printf("CERT_KEY_PROV_INFO_PROP_ID: %s, %s, type %u, flags %#x, params: %u,%p, keyspec %#x\n",
                      debugstr_w(pinfo->pwszContainerName), debugstr_w(pinfo->pwszProvName), pinfo->dwProvType,
                      pinfo->dwFlags, pinfo->cProvParam, pinfo->rgProvParam, pinfo->dwKeySpec);

            if (!CertSetCertificateContextProperty(ctx, cert->prop[i].id, 0, cert->prop[i].data.pbData))
                printf("CertSetCertificateContextProperty(%u) error %#x\n", cert->prop[i].id, GetLastError());
            break;
        }

        default:
            if (!CertSetCertificateContextProperty(ctx, cert->prop[i].id, 0, &cert->prop[i].data))
                printf("CertSetCertificateContextProperty(%u) error %#x\n", cert->prop[i].id, GetLastError());
            break;
        }
    }

    return TRUE;
}

static BOOL save_store_info(const char *store_name, struct store_info *store)
{
    HCERTSTORE hstore;
    PCCERT_CONTEXT new_ctx;
    DWORD i;

    printf("Saving certificates to %s store\n", store_name);

    hstore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                           CERT_SYSTEM_STORE_CURRENT_USER, store_name);
    if (!hstore)
    {
        printf("CertOpenStore(%s) error %#x\n", store_name, GetLastError());
        return FALSE;
    }

    for (i = 0; i < store->cert_count; i++)
    {
        printf("Saving certificate %s to %s store\n", wine_dbgstr_w(store->cert[i].subject), store_name);

        if (!CertAddEncodedCertificateToStore(hstore, store->cert[i].dwCertEncodingType,
                                               store->cert[i].data.pbData, store->cert[i].data.cbData,
                                               CERT_STORE_ADD_REPLACE_EXISTING, &new_ctx))
        {
            printf("CertAddEncodedCertificateToStore error %#x\n", GetLastError());
            break;
        }

        save_prop_info(new_ctx, &store->cert[i]);
    }

    CertControlStore(hstore, 0, CERT_STORE_CTRL_COMMIT, NULL);
    CertCloseStore(hstore, 0);

    return TRUE;
}

static void setup_providers(void)
{
    HKEY hkey_provider, hkey_provider_types, hkey;
    DWORD i = 0, type, size;

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\Defaults\\Provider", &hkey_provider))
    {
        printf("failed to open provider key\n");
        return;
    }

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\Defaults\\Provider Types", &hkey_provider_types))
    {
        printf("failed to open provider types key\n");
        return;
    }

    while (pCryptEnumProvidersA(i, NULL, 0, &type, NULL, &size))
    {
        char *name = xmalloc(size);

        if (pCryptEnumProvidersA(i, NULL, 0, &type, name, &size))
        {
            char buf[32];

            printf("Adding: provider %s, type %u\n", name, type);

            if (RegCreateKeyA(hkey_provider, name, &hkey))
            {
                printf("failed to create key %s\n", name);
                return;
            }

            if (RegSetValueExA(hkey, "Type", 0, REG_DWORD, (const BYTE *)&type, sizeof(type)))
            {
                printf("failed to set Type value %u\n", type);
                return;
            }

            if (RegSetValueExA(hkey, "Image Path", 0, REG_SZ, (const BYTE *)proxy_dll, sizeof(proxy_dll)))
            {
                printf("failed to set Image Path value\n");
                return;
            }

            RegCloseKey(hkey);

            sprintf(buf, "Type %03u", type);

            if (RegCreateKeyA(hkey_provider_types, buf, &hkey))
            {
                printf("failed to create key %s\n", buf);
                return;
            }

            if (RegSetValueExA(hkey, "Name", 0, REG_SZ, (BYTE *)name, strlen(name) + 1))
            {
                printf("failed to set Name value\n");
                return;
            }

            RegCloseKey(hkey);
        }

        free(name);
        i++;
    }

    RegCloseKey(hkey_provider);
    RegCloseKey(hkey_provider_types);
}

/* Crypto Pro implementation is broken, it doesn't use WINAPI for a callback */
static BOOL /*WINAPI*/ enum_oid_info(PCCRYPT_OID_INFO info, void *arg)
{
    static const WCHAR nameW[] = { 'N','a','m','e',0 };
    static const WCHAR algidW[] = { 'A','l','g','i','d',0 };
    static const WCHAR extraW[] = { 'E','x','t','r','a','I','n','f','o',0 };
    HKEY hkey_main = arg, hkey;
    WCHAR name[1024];
    char key_name[1024];

    printf("Adding: OID %s, name %S, GroupId %u, Algid %#x, ExtraInfo %u bytes\n",
           info->pszOID, (wchar_t *)info->pwszName, info->dwGroupId,
           info->u.Algid, info->ExtraInfo.cbData);

    sprintf(key_name, "%s!%u", info->pszOID, info->dwGroupId);

    if (RegCreateKeyA(hkey_main, key_name, &hkey))
    {
        printf("failed to create key %s\n", key_name);
        return FALSE;
    }

    wchar4_to_wchar2((const int *)info->pwszName, name);
    RegSetValueExW(hkey, nameW, 0, REG_SZ, (BYTE *)name, (lstrlenW(name) + 1) * sizeof(WCHAR));

    if (info->u.Algid)
        RegSetValueExW(hkey, algidW, 0, REG_DWORD, (BYTE *)&info->u.Algid, sizeof(info->u.Algid));

    if (info->ExtraInfo.cbData && info->ExtraInfo.pbData)
        RegSetValueExW(hkey, extraW, 0, REG_BINARY, info->ExtraInfo.pbData, info->ExtraInfo.cbData);

    RegCloseKey(hkey);

    return TRUE;
}

static BOOL register_publickey_converters(HKEY hkey_main)
{
    static const struct
    {
        const char *oid;
        const char *dll;
        const char *function;
    } converter_info[] =
    {
        { "1.2.643.2.2.19", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.643.2.2.98", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.643.7.1.1.1.1", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.643.7.1.1.1.2", proxy_dll, "CryptDllConvertPublicKeyInfo" },
        { "1.2.840.10045.2.1", proxy_dll, "CryptDllConvertPublicKeyInfo" },
    };
    DWORD i;
    HKEY hkey;

    for (i = 0; i < ARRAY_SIZE(converter_info); i++)
    {
        if (RegCreateKeyA(hkey_main, converter_info[i].oid, &hkey))
        {
            printf("failed to create key %s\n", converter_info[i].oid);
            return FALSE;
        }
        RegSetValueExA(hkey, "Dll", 0, REG_SZ, (BYTE *)converter_info[i].dll, strlen(converter_info[i].dll));
        RegSetValueExA(hkey, "FuncName", 0, REG_SZ, (BYTE *)converter_info[i].function, strlen(converter_info[i].function));
        RegCloseKey(hkey);
    }

    return TRUE;
}

static BOOL register_publickey_encoders(HKEY hkey_main)
{
    static const struct
    {
        const char *oid;
        const char *dll;
        const char *function;
    } converter_info[] =
    {
        { "1.2.643.2.2.19", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.643.2.2.98", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.643.7.1.1.1.1", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.643.7.1.1.1.2", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
        { "1.2.840.10045.2.1", proxy_dll, "CryptDllEncodePublicKeyAndParameters" },
    };
    DWORD i;
    HKEY hkey;

    for (i = 0; i < ARRAY_SIZE(converter_info); i++)
    {
        if (RegCreateKeyA(hkey_main, converter_info[i].oid, &hkey))
        {
            printf("failed to create key %s\n", converter_info[i].oid);
            return FALSE;
        }
        RegSetValueExA(hkey, "Dll", 0, REG_SZ, (BYTE *)converter_info[i].dll, strlen(converter_info[i].dll));
        RegSetValueExA(hkey, "FuncName", 0, REG_SZ, (BYTE *)converter_info[i].function, strlen(converter_info[i].function));
        RegCloseKey(hkey);
    }

    return TRUE;
}

static void setup_oid_info(void)
{
    HKEY hkey_main;

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptDllFindOIDInfo", &hkey_main))
    {
        printf("failed to open OID info key\n");
        return;
    }
    pCryptEnumOIDInfo(0, 0, hkey_main, (PFN_CRYPT_ENUM_OID_INFO)enum_oid_info);
    RegCloseKey(hkey_main);

    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\OID\\EncodingType 1\\CryptDllConvertPublicKeyInfo", &hkey_main))
    {
        printf("failed to open OID info key\n");
        return;
    }
    register_publickey_converters(hkey_main);
    RegCloseKey(hkey_main);


    if (RegCreateKeyA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Cryptography\\OID\\EncodingType 1\\CryptDllEncodePublicKeyAndParameters", &hkey_main))
    {
        printf("failed to open OID info key\n");
        return;
    }
    register_publickey_encoders(hkey_main);
    RegCloseKey(hkey_main);
}

int __cdecl wmain(int argc, WCHAR *argv[])
{
    struct store_info root_store, my_store, ca_store;

    if (argc > 1)
    {
        if (argv[1][0] == '-' && argv[1][1] == 'v')
            verbose = TRUE;
    }

    if (!load_cpcsp()) return -1;

    setup_providers();
    setup_oid_info();

    printf("======================= Linux store =======================\n");

    read_store_info("CA", &ca_store);
    read_store_info("Root", &root_store);
    read_store_info("My", &my_store);

    printf("======================= Wine store =======================\n");

    save_store_info("CA", &ca_store);
    save_store_info("Root", &root_store);
    save_store_info("My", &my_store);

    return 0;
}
