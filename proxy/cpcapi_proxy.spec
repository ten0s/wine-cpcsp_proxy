# capi10
@ stdcall CP_CryptEnumProvidersA(long ptr long ptr str ptr)
@ stdcall CP_CryptAcquireContextA(ptr str str long long)
@ stdcall CP_CryptAcquireContextW(ptr wstr wstr long long)
@ stdcall CP_CryptGetProvParam(long long ptr ptr long)
@ stdcall CP_CryptSetProvParam(long long ptr long)
@ stdcall CP_CryptGetUserKey(long long ptr)
@ stdcall CP_CryptDestroyKey(long)
@ stdcall CP_CryptReleaseContext(long long)
@ stdcall CP_CryptEnumOIDInfo(long long ptr ptr)

# capi20
@ stdcall CP_CryptAcquireCertificatePrivateKey(ptr long ptr ptr ptr ptr)
@ stdcall CP_CryptEncodeObjectEx(long str ptr long ptr ptr ptr)
@ stdcall CP_CryptDecodeObjectEx(long str ptr long long ptr ptr ptr)
@ stdcall CP_CryptExportPublicKeyInfo(long long long ptr ptr)
@ stdcall CP_CertComparePublicKeyInfo(long ptr ptr)
@ stdcall CP_CertGetNameStringA(ptr long long ptr str long)
@ stdcall CP_CertOpenStore(str long long long ptr)
@ stdcall CP_CertOpenSystemStoreA(long str)
@ stdcall CP_CertOpenSystemStoreW(long wstr)
@ stdcall CP_CertControlStore(long long long ptr)
@ stdcall CP_CertCloseStore(long long)
@ stdcall CP_CertEnumCertificatesInStore(long ptr)
@ stdcall CP_CertFindCertificateInStore(long long long long ptr ptr)
@ stdcall CP_CertDeleteCertificateFromStore(ptr)
@ stdcall CP_CertGetIssuerCertificateFromStore(long ptr ptr ptr)
@ stdcall CP_CertCreateCertificateContext(long ptr long)
@ stdcall CP_CertDuplicateCertificateContext(ptr)
@ stdcall CP_CertEnumCertificateContextProperties(ptr long)
@ stdcall CP_CertGetCertificateContextProperty(ptr long ptr ptr)
@ stdcall CP_CertSetCertificateContextProperty(ptr long long ptr)
@ stdcall CP_CertAddCertificateContextToStore(long ptr long ptr)
@ stdcall CP_CertFreeCertificateContext(ptr)
@ stdcall CP_CertGetCertificateChain(long ptr ptr long ptr long ptr ptr)
@ stdcall CP_CertFreeCertificateChain(ptr)
