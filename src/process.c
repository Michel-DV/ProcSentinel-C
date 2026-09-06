#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "procsentinel/procsentinel.h"

#pragma comment(lib, "advapi32.lib")

static DWORD parent_pid_of(DWORD pid, wchar_t *image, size_t image_count) {
    HANDLE snap;
    PROCESSENTRY32W pe;
    DWORD parent = 0;
    if (image && image_count) image[0] = L'\0';
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                parent = pe.th32ParentProcessID;
                if (image && image_count) wcsncpy_s(image, image_count, pe.szExeFile, _TRUNCATE);
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return parent;
}

static void process_user(HANDLE process, wchar_t *out, size_t count) {
    HANDLE token = NULL;
    DWORD needed = 0;
    TOKEN_USER *tu = NULL;
    wchar_t name[128] = L"";
    wchar_t domain[128] = L"";
    DWORD name_len = 128, domain_len = 128;
    SID_NAME_USE use;
    if (!out || !count) return;
    wcscpy_s(out, count, L"unknown");
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return;
    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    tu = (TOKEN_USER *)malloc(needed);
    if (tu && GetTokenInformation(token, TokenUser, tu, needed, &needed) &&
        LookupAccountSidW(NULL, tu->User.Sid, name, &name_len, domain, &domain_len, &use)) {
        if (domain[0]) swprintf_s(out, count, L"%ls\\%ls", domain, name);
        else wcsncpy_s(out, count, name, _TRUNCATE);
    }
    free(tu);
    CloseHandle(token);
}

static void process_integrity(HANDLE process, wchar_t *out, size_t count) {
    HANDLE token = NULL;
    DWORD needed = 0;
    TOKEN_MANDATORY_LABEL *tml = NULL;
    DWORD rid = 0;
    if (!out || !count) return;
    wcscpy_s(out, count, L"unknown");
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &needed);
    tml = (TOKEN_MANDATORY_LABEL *)malloc(needed);
    if (tml && GetTokenInformation(token, TokenIntegrityLevel, tml, needed, &needed)) {
        DWORD subcount = *GetSidSubAuthorityCount(tml->Label.Sid);
        rid = *GetSidSubAuthority(tml->Label.Sid, subcount - 1);
        if (rid < SECURITY_MANDATORY_LOW_RID) wcscpy_s(out, count, L"untrusted");
        else if (rid < SECURITY_MANDATORY_MEDIUM_RID) wcscpy_s(out, count, L"low");
        else if (rid < SECURITY_MANDATORY_HIGH_RID) wcscpy_s(out, count, L"medium");
        else if (rid < SECURITY_MANDATORY_SYSTEM_RID) wcscpy_s(out, count, L"high");
        else wcscpy_s(out, count, L"system");
    }
    free(tml);
    CloseHandle(token);
}

static const wchar_t *machine_name(USHORT machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386: return L"x86";
        case IMAGE_FILE_MACHINE_AMD64: return L"x64";
        case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
        case IMAGE_FILE_MACHINE_ARMNT: return L"ARM32";
        case IMAGE_FILE_MACHINE_UNKNOWN: return L"native/unknown";
        default: return L"other";
    }
}

static void process_architecture(HANDLE process, wchar_t *out, size_t count) {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!out || !count) return;
    wcscpy_s(out, count, L"unknown");
    if (IsWow64Process2(process, &process_machine, &native_machine)) {
        if (process_machine == IMAGE_FILE_MACHINE_UNKNOWN) wcsncpy_s(out, count, machine_name(native_machine), _TRUNCATE);
        else swprintf_s(out, count, L"%ls on %ls", machine_name(process_machine), machine_name(native_machine));
    }
}

int ps_analyze_file(const wchar_t *path, PsFileReport *out) {
    if (!path || !out) return 0;
    ZeroMemory(out, sizeof(*out));
    wcsncpy_s(out->path, _countof(out->path), path, _TRUNCATE);
    ps_sha256_file(path, out->sha256);
    out->signature = ps_verify_signature(path, &out->signature_code);
    ps_analyze_pe_file(path, &out->pe);
    out->score = ps_score_file(out);
    return out->pe.valid || out->sha256[0] != '\0';
}

static int fill_process_details(PsProcessReport *out, int collect_network, int analyze_image) {
    HANDLE process;
    DWORD path_len;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, out->pid);
    if (!process) return 0;
    out->accessible = 1;
    path_len = (DWORD)_countof(out->path);
    if (QueryFullProcessImageNameW(process, 0, out->path, &path_len) && analyze_image) {
        ps_analyze_file(out->path, &out->file);
    }
    process_user(process, out->user, _countof(out->user));
    process_integrity(process, out->integrity, _countof(out->integrity));
    process_architecture(process, out->architecture, _countof(out->architecture));
    CloseHandle(process);
    if (collect_network) ps_collect_tcp4_for_pid(out->pid, out->tcp, PS_MAX_TCP, &out->tcp_count);
    return 1;
}

int ps_analyze_process(DWORD pid, PsProcessReport *out) {
    if (!out) return 0;
    ZeroMemory(out, sizeof(*out));
    out->pid = pid;
    out->parent_pid = parent_pid_of(pid, out->image_name, _countof(out->image_name));
    return fill_process_details(out, 1, 1);
}

int ps_enumerate_processes(PsProcessReport **out, size_t *count, int deep_scan) {
    HANDLE snap;
    PROCESSENTRY32W pe;
    PsProcessReport *items = NULL;
    size_t used = 0, cap = 128;
    if (!out || !count) return 0;
    *out = NULL; *count = 0;
    items = (PsProcessReport *)calloc(cap, sizeof(*items));
    if (!items) return 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { free(items); return 0; }
    ZeroMemory(&pe, sizeof(pe)); pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (used == cap) {
                cap *= 2;
                PsProcessReport *tmp = (PsProcessReport *)realloc(items, cap * sizeof(*items));
                if (!tmp) { CloseHandle(snap); free(items); return 0; }
                items = tmp;
                ZeroMemory(items + used, (cap - used) * sizeof(*items));
            }
            items[used].pid = pe.th32ProcessID;
            items[used].parent_pid = pe.th32ParentProcessID;
            wcsncpy_s(items[used].image_name, _countof(items[used].image_name), pe.szExeFile, _TRUNCATE);
            if (deep_scan) fill_process_details(&items[used], 0, 0);
            used++;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (deep_scan) {
        for (size_t i = 0; i < used; ++i) {
            if (!items[i].path[0]) continue;
            size_t match = i;
            for (size_t j = 0; j < i; ++j) {
                if (items[j].path[0] && _wcsicmp(items[j].path, items[i].path) == 0) {
                    match = j;
                    break;
                }
            }
            if (match < i) items[i].file = items[match].file;
            else ps_analyze_file(items[i].path, &items[i].file);
        }
        ps_collect_tcp4_for_processes(items, used);
    }
    *out = items; *count = used;
    return 1;
}

void ps_free_processes(PsProcessReport *items) { free(items); }
