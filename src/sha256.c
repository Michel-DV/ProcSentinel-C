#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include "procsentinel/procsentinel.h"

#pragma comment(lib, "bcrypt.lib")

int ps_sha256_file(const wchar_t *path, char out_hex[65]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    DWORD object_len = 0, cb = 0, hash_len = 0;
    unsigned char *object = NULL;
    unsigned char digest[32];
    FILE *fp = NULL;
    unsigned char buf[65536];
    size_t n;
    int ok = 0;

    if (!path || !out_hex) return 0;
    out_hex[0] = '\0';

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) goto done;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_len, sizeof(object_len), &cb, 0) != 0) goto done;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_len, sizeof(hash_len), &cb, 0) != 0 || hash_len != sizeof(digest)) goto done;

    object = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, object_len);
    if (!object) goto done;
    if (BCryptCreateHash(alg, &hash, object, object_len, NULL, 0, 0) != 0) goto done;

    fp = _wfopen(path, L"rb");
    if (!fp) goto done;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (BCryptHashData(hash, buf, (ULONG)n, 0) != 0) goto done;
    }
    if (ferror(fp)) goto done;
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) != 0) goto done;

    for (size_t i = 0; i < sizeof(digest); ++i) {
        static const char hex[] = "0123456789abcdef";
        out_hex[i * 2] = hex[digest[i] >> 4];
        out_hex[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out_hex[64] = '\0';
    ok = 1;

done:
    if (fp) fclose(fp);
    if (hash) BCryptDestroyHash(hash);
    if (object) HeapFree(GetProcessHeap(), 0, object);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}
