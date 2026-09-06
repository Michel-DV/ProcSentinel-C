#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <iphlpapi.h>
#include "procsentinel/procsentinel.h"

static int failures = 0;

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); failures++; } } while (0)

static void test_entropy(void) {
    unsigned char zeros[1024] = {0};
    unsigned char uniform[256];
    for (int i = 0; i < 256; ++i) uniform[i] = (unsigned char)i;
    CHECK(fabs(ps_entropy(zeros, sizeof(zeros))) < 0.0001);
    CHECK(fabs(ps_entropy(uniform, sizeof(uniform)) - 8.0) < 0.0001);
    CHECK(ps_entropy(NULL, 0) == 0.0);
}

static void test_scoring(void) {
    PsFileReport r;
    ZeroMemory(&r, sizeof(r));
    CHECK(ps_score_file(NULL) == 0);

    r.signature = PS_SIGNATURE_TRUSTED;
    r.pe.valid = 1;
    CHECK(ps_score_file(&r) == 0);

    r.signature = PS_SIGNATURE_UNSIGNED;
    CHECK(ps_score_file(&r) == 10);

    r.pe.has_wx_section = 1;
    r.pe.high_entropy_executable_section = 1;
    r.pe.entrypoint_in_writable_section = 1;
    CHECK(ps_score_file(&r) == 90);

    r.signature = PS_SIGNATURE_INVALID;
    CHECK(ps_score_file(&r) == 100);
}

static void test_status_helpers(void) {
    CHECK(strcmp(ps_signature_name(PS_SIGNATURE_TRUSTED), "trusted") == 0);
    CHECK(strcmp(ps_signature_name(PS_SIGNATURE_UNSIGNED), "unsigned") == 0);
    CHECK(strcmp(ps_signature_name(PS_SIGNATURE_INVALID), "invalid") == 0);
    CHECK(strcmp(ps_signature_name(PS_SIGNATURE_UNKNOWN), "unknown") == 0);
    CHECK(strcmp(ps_tcp_state_name(MIB_TCP_STATE_LISTEN), "LISTEN") == 0);
    CHECK(strcmp(ps_tcp_state_name(MIB_TCP_STATE_ESTAB), "ESTABLISHED") == 0);
    CHECK(strcmp(ps_tcp_state_name(0xffffffffu), "UNKNOWN") == 0);
}

static void test_invalid_pe(void) {
    wchar_t temp_dir[MAX_PATH] = L"";
    wchar_t temp_file[MAX_PATH] = L"";
    FILE *fp = NULL;
    PsPeInfo pe;
    DWORD n = GetTempPathW((DWORD)_countof(temp_dir), temp_dir);
    CHECK(n > 0 && n < _countof(temp_dir));
    if (!(n > 0 && n < _countof(temp_dir))) return;
    CHECK(GetTempFileNameW(temp_dir, L"psc", 0, temp_file) != 0);
    if (!temp_file[0]) return;
    CHECK(_wfopen_s(&fp, temp_file, L"wb") == 0 && fp != NULL);
    if (fp) {
        static const unsigned char fixture[] = "ProcSentinel synthetic non-PE fixture\n";
        CHECK(fwrite(fixture, 1, sizeof(fixture) - 1, fp) == sizeof(fixture) - 1);
        fclose(fp);
        fp = NULL;
        CHECK(ps_analyze_pe_file(temp_file, &pe) == 0);
    }
    DeleteFileW(temp_file);
}

static void test_self_pe(void) {
    wchar_t path[PS_MAX_WPATH];
    DWORD n = GetModuleFileNameW(NULL, path, (DWORD)_countof(path));
    PsPeInfo pe;
    char hash[65];
    CHECK(n > 0 && n < _countof(path));
    CHECK(ps_analyze_pe_file(path, &pe) == 1);
    CHECK(pe.valid == 1);
    CHECK(pe.section_count > 0);
    CHECK(ps_sha256_file(path, hash) == 1);
    CHECK(strlen(hash) == 64);
}

int main(void) {
    test_entropy();
    test_scoring();
    test_status_helpers();
    test_invalid_pe();
    test_self_pe();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    puts("all tests passed");
    return 0;
}
