#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "procsentinel/procsentinel.h"

static void usage(void) {
    puts("ProcSentinel-C " PS_VERSION " - Windows endpoint and PE triage\n");
    puts("Usage:");
    puts("  procsentinel.exe scan [--json] [--quick]");
    puts("  procsentinel.exe pid <PID> [--json]");
    puts("  procsentinel.exe file <PATH> [--json]");
    puts("  procsentinel.exe --version");
    puts("\nRead-only defensive triage. No process modification or memory injection is performed.");
}

static int has_flag(int argc, wchar_t **argv, const wchar_t *flag) {
    for (int i = 1; i < argc; ++i) if (_wcsicmp(argv[i], flag) == 0) return 1;
    return 0;
}

int wmain(int argc, wchar_t **argv) {
    int json = has_flag(argc, argv, L"--json");
    if (argc < 2) { usage(); return 2; }
    if (_wcsicmp(argv[1], L"--version") == 0) { puts(PS_VERSION); return 0; }
    if (_wcsicmp(argv[1], L"--help") == 0 || _wcsicmp(argv[1], L"-h") == 0) { usage(); return 0; }

    if (_wcsicmp(argv[1], L"file") == 0) {
        PsFileReport r;
        if (argc < 3) { fputs("error: file path required\n", stderr); return 2; }
        if (!ps_analyze_file(argv[2], &r)) { fputs("error: unable to analyze file\n", stderr); return 1; }
        if (json) ps_print_file_json(&r); else ps_print_file_text(&r);
        return 0;
    }

    if (_wcsicmp(argv[1], L"pid") == 0) {
        wchar_t *end = NULL;
        unsigned long value;
        PsProcessReport r;
        if (argc < 3) { fputs("error: PID required\n", stderr); return 2; }
        value = wcstoul(argv[2], &end, 10);
        if (!end || *end || value > 0xffffffffUL) { fputs("error: invalid PID\n", stderr); return 2; }
        if (!ps_analyze_process((DWORD)value, &r)) { fputs("error: process unavailable or access denied\n", stderr); return 1; }
        if (json) ps_print_process_json(&r); else ps_print_process_text(&r, 1);
        return 0;
    }

    if (_wcsicmp(argv[1], L"scan") == 0) {
        PsProcessReport *items = NULL;
        size_t count = 0;
        int quick = has_flag(argc, argv, L"--quick");
        if (!ps_enumerate_processes(&items, &count, quick ? 0 : 1)) { fputs("error: process enumeration failed\n", stderr); return 1; }
        if (json) {
            putchar('[');
            for (size_t i = 0; i < count; ++i) {
                if (i) putchar(',');
                if (quick) {
                    char name[1024] = "";
                    ps_wide_to_utf8(items[i].image_name, name, sizeof(name));
                    printf("{\"pid\":%lu,\"parent_pid\":%lu,\"image\":", (unsigned long)items[i].pid, (unsigned long)items[i].parent_pid);
                    ps_json_escape(stdout, name); putchar('}');
                } else {
                    /* Compact JSON object for scan mode. */
                    char name[1024] = "", path[PS_MAX_PATH_UTF8] = "";
                    ps_wide_to_utf8(items[i].image_name, name, sizeof(name));
                    ps_wide_to_utf8(items[i].path, path, sizeof(path));
                    printf("{\"pid\":%lu,\"parent_pid\":%lu,\"image\":", (unsigned long)items[i].pid, (unsigned long)items[i].parent_pid);
                    ps_json_escape(stdout, name); printf(",\"path\":"); ps_json_escape(stdout, path);
                    printf(",\"score\":%d,\"accessible\":%s}", items[i].file.score, items[i].accessible ? "true" : "false");
                }
            }
            puts("]");
        } else {
            printf("ProcSentinel-C %s\nProcesses: %zu\n\n", PS_VERSION, count);
            puts("PID     PPID    IMAGE                        TRIAGE");
            puts("------- ------- ---------------------------- ----------------");
            for (size_t i = 0; i < count; ++i) {
                if (quick) {
                    char name[1024] = "";
                    ps_wide_to_utf8(items[i].image_name, name, sizeof(name));
                    printf("%-7lu %-7lu %-28s %s\n", (unsigned long)items[i].pid,
                           (unsigned long)items[i].parent_pid, name[0] ? name : "?", "inventory");
                } else {
                    ps_print_process_text(&items[i], 0);
                }
            }
        }
        ps_free_processes(items);
        return 0;
    }

    usage();
    return 2;
}
