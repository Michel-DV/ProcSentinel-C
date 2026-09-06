#ifndef PROCSENTINEL_H
#define PROCSENTINEL_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PS_VERSION "1.0.0"
#define PS_MAX_SECTIONS 32
#define PS_MAX_IMPORTS 128
#define PS_MAX_TCP 128
#define PS_MAX_PATH_UTF8 16384
#define PS_MAX_WPATH 4096

typedef enum PsSignatureStatus {
    PS_SIGNATURE_TRUSTED = 0,
    PS_SIGNATURE_UNSIGNED,
    PS_SIGNATURE_INVALID,
    PS_SIGNATURE_UNKNOWN
} PsSignatureStatus;

typedef struct PsSectionInfo {
    char name[9];
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_size;
    uint32_t characteristics;
    double entropy;
    int contains_entrypoint;
} PsSectionInfo;

typedef struct PsImportInfo {
    char dll[64];
    char symbol[128];
} PsImportInfo;

typedef struct PsPeInfo {
    int valid;
    int is_64bit;
    uint16_t machine;
    uint32_t timestamp;
    uint32_t entry_rva;
    size_t section_count;
    PsSectionInfo sections[PS_MAX_SECTIONS];
    size_t import_count;
    PsImportInfo imports[PS_MAX_IMPORTS];
    int has_wx_section;
    int high_entropy_executable_section;
    int entrypoint_in_writable_section;
    unsigned suspicious_api_count;
} PsPeInfo;

typedef struct PsTcpConnection {
    char local_addr[64];
    uint16_t local_port;
    char remote_addr[64];
    uint16_t remote_port;
    uint32_t state;
} PsTcpConnection;

typedef struct PsFileReport {
    wchar_t path[PS_MAX_WPATH];
    char sha256[65];
    PsSignatureStatus signature;
    LONG signature_code;
    PsPeInfo pe;
    int score;
} PsFileReport;

typedef struct PsProcessReport {
    DWORD pid;
    DWORD parent_pid;
    wchar_t image_name[MAX_PATH];
    wchar_t path[PS_MAX_WPATH];
    wchar_t user[256];
    wchar_t integrity[64];
    wchar_t architecture[64];
    int accessible;
    PsFileReport file;
    size_t tcp_count;
    PsTcpConnection tcp[PS_MAX_TCP];
} PsProcessReport;

int ps_analyze_pe_file(const wchar_t *path, PsPeInfo *out);
double ps_entropy(const unsigned char *data, size_t len);
int ps_sha256_file(const wchar_t *path, char out_hex[65]);
PsSignatureStatus ps_verify_signature(const wchar_t *path, LONG *status_code);
int ps_score_file(const PsFileReport *report);
int ps_analyze_file(const wchar_t *path, PsFileReport *out);
int ps_analyze_process(DWORD pid, PsProcessReport *out);
int ps_enumerate_processes(PsProcessReport **out, size_t *count, int deep_scan);
void ps_free_processes(PsProcessReport *items);
int ps_collect_tcp4_for_pid(DWORD pid, PsTcpConnection *out, size_t capacity, size_t *count);
int ps_collect_tcp4_for_processes(PsProcessReport *items, size_t item_count);
const char *ps_signature_name(PsSignatureStatus status);
const char *ps_tcp_state_name(uint32_t state);
int ps_wide_to_utf8(const wchar_t *src, char *dst, size_t dst_size);
void ps_json_escape(FILE *fp, const char *s);
void ps_print_file_text(const PsFileReport *r);
void ps_print_file_json(const PsFileReport *r);
void ps_print_process_text(const PsProcessReport *r, int detailed);
void ps_print_process_json(const PsProcessReport *r);

#ifdef __cplusplus
}
#endif

#endif
