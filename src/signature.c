#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include "procsentinel/procsentinel.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

PsSignatureStatus ps_verify_signature(const wchar_t *path, LONG *status_code) {
    WINTRUST_FILE_INFO fi;
    WINTRUST_DATA data;
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status;

    ZeroMemory(&fi, sizeof(fi));
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;

    ZeroMemory(&data, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fi;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_SAFER_FLAG;

    status = WinVerifyTrust(NULL, &policy, &data);
    if (status_code) *status_code = status;

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy, &data);

    if (status == ERROR_SUCCESS) return PS_SIGNATURE_TRUSTED;
    if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_PROVIDER_UNKNOWN)
        return PS_SIGNATURE_UNSIGNED;
    if (status == TRUST_E_EXPLICIT_DISTRUST || status == TRUST_E_SUBJECT_NOT_TRUSTED || status == CERT_E_UNTRUSTEDROOT || status == CERT_E_EXPIRED)
        return PS_SIGNATURE_INVALID;
    return PS_SIGNATURE_UNKNOWN;
}
