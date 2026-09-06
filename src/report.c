#include <stdio.h>
#include <string.h>
#include "procsentinel/procsentinel.h"

static const char *risk_label(int score) {
    if (score >= 70) return "HIGH";
    if (score >= 40) return "MEDIUM";
    if (score >= 15) return "LOW";
    return "INFO";
}

static void path_utf8(const wchar_t *w, char out[PS_MAX_PATH_UTF8]) {
    if (!ps_wide_to_utf8(w, out, PS_MAX_PATH_UTF8)) strcpy(out, "<unavailable>");
}

void ps_print_file_text(const PsFileReport *r) {
    char path[PS_MAX_PATH_UTF8];
    path_utf8(r->path, path);
    printf("Path              : %s\n", path);
    printf("SHA-256           : %s\n", r->sha256[0] ? r->sha256 : "unavailable");
    printf("Signature         : %s\n", ps_signature_name(r->signature));
    printf("Risk score        : %d / 100 (%s)\n", r->score, risk_label(r->score));
    if (!r->pe.valid) {
        puts("PE analysis        : unavailable / not a valid PE image");
        return;
    }
    printf("PE architecture   : %s\n", r->pe.is_64bit ? "PE32+ / 64-bit" : "PE32 / 32-bit");
    printf("Machine           : 0x%04x\n", r->pe.machine);
    printf("Entry RVA         : 0x%08x\n", r->pe.entry_rva);
    printf("Sections          : %zu\n", r->pe.section_count);
    printf("Imports captured  : %zu\n", r->pe.import_count);
    printf("Dual-use APIs     : %u (informational)\n", r->pe.suspicious_api_count);
    puts("\nFindings");
    if (r->pe.has_wx_section) puts("  [HIGH] Writable + executable PE section");
    if (r->pe.high_entropy_executable_section) puts("  [MED]  High-entropy executable section");
    if (r->pe.entrypoint_in_writable_section) puts("  [HIGH] Entry point resides in a writable section");
    if (r->signature == PS_SIGNATURE_UNSIGNED) puts("  [LOW]  File is unsigned");
    if (r->signature == PS_SIGNATURE_INVALID) puts("  [MED]  Digital signature is invalid/untrusted");
    if (!r->pe.has_wx_section && !r->pe.high_entropy_executable_section && !r->pe.entrypoint_in_writable_section && r->signature == PS_SIGNATURE_TRUSTED)
        puts("  [INFO] No high-signal PE triage findings");

    puts("\nPE sections");
    for (size_t i = 0; i < r->pe.section_count; ++i) {
        const PsSectionInfo *s = &r->pe.sections[i];
        printf("  %-8s RVA=0x%08x raw=%-8u entropy=%.2f %c%c%c%s\n",
               s->name[0] ? s->name : "<unnamed>", s->virtual_address, s->raw_size, s->entropy,
               (s->characteristics & IMAGE_SCN_MEM_READ) ? 'R' : '-',
               (s->characteristics & IMAGE_SCN_MEM_WRITE) ? 'W' : '-',
               (s->characteristics & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-',
               s->contains_entrypoint ? "  <entry>" : "");
    }

    if (r->pe.import_count) {
        puts("\nSelected imports");
        size_t limit = r->pe.import_count < 24 ? r->pe.import_count : 24;
        for (size_t i = 0; i < limit; ++i)
            printf("  %s!%s\n", r->pe.imports[i].dll, r->pe.imports[i].symbol);
        if (limit < r->pe.import_count) printf("  ... %zu more\n", r->pe.import_count - limit);
    }
}

void ps_print_file_json(const PsFileReport *r) {
    char path[PS_MAX_PATH_UTF8];
    path_utf8(r->path, path);
    printf("{");
    printf("\"path\":"); ps_json_escape(stdout, path);
    printf(",\"sha256\":"); ps_json_escape(stdout, r->sha256);
    printf(",\"signature\":"); ps_json_escape(stdout, ps_signature_name(r->signature));
    printf(",\"score\":%d", r->score);
    printf(",\"pe\":{\"valid\":%s,\"is_64bit\":%s,\"machine\":%u,\"entry_rva\":%u,\"sections\":[",
           r->pe.valid ? "true" : "false", r->pe.is_64bit ? "true" : "false", r->pe.machine, r->pe.entry_rva);
    for (size_t i = 0; i < r->pe.section_count; ++i) {
        const PsSectionInfo *s = &r->pe.sections[i];
        if (i) putchar(',');
        printf("{\"name\":"); ps_json_escape(stdout, s->name);
        printf(",\"entropy\":%.4f,\"rva\":%u,\"raw_size\":%u,\"rwx\":%s,\"entry\":%s}",
               s->entropy, s->virtual_address, s->raw_size,
               ((s->characteristics & IMAGE_SCN_MEM_WRITE) && (s->characteristics & IMAGE_SCN_MEM_EXECUTE)) ? "true" : "false",
               s->contains_entrypoint ? "true" : "false");
    }
    printf("],\"findings\":{\"wx_section\":%s,\"high_entropy_exec\":%s,\"entrypoint_writable\":%s,\"dual_use_api_count\":%u}}}\n",
           r->pe.has_wx_section ? "true" : "false",
           r->pe.high_entropy_executable_section ? "true" : "false",
           r->pe.entrypoint_in_writable_section ? "true" : "false",
           r->pe.suspicious_api_count);
}

void ps_print_process_text(const PsProcessReport *r, int detailed) {
    char name[1024], path[PS_MAX_PATH_UTF8], user[1024], integrity[256], arch[256];
    ps_wide_to_utf8(r->image_name, name, sizeof(name));
    ps_wide_to_utf8(r->path, path, sizeof(path));
    ps_wide_to_utf8(r->user, user, sizeof(user));
    ps_wide_to_utf8(r->integrity, integrity, sizeof(integrity));
    ps_wide_to_utf8(r->architecture, arch, sizeof(arch));
    if (!detailed) {
        printf("%-7lu %-7lu %-28s score=%-3d %s\n", (unsigned long)r->pid, (unsigned long)r->parent_pid,
               name[0] ? name : "?", r->file.score, r->accessible ? "" : "[restricted]");
        return;
    }
    printf("PID               : %lu\n", (unsigned long)r->pid);
    printf("Parent PID        : %lu\n", (unsigned long)r->parent_pid);
    printf("Image             : %s\n", name[0] ? name : "unknown");
    printf("Path              : %s\n", path[0] ? path : "unavailable");
    printf("User              : %s\n", user[0] ? user : "unknown");
    printf("Integrity         : %s\n", integrity[0] ? integrity : "unknown");
    printf("Architecture      : %s\n", arch[0] ? arch : "unknown");
    printf("TCP/IPv4 entries  : %zu\n", r->tcp_count);
    if (r->path[0]) {
        putchar('\n');
        ps_print_file_text(&r->file);
    }
    if (r->tcp_count) {
        puts("\nTCP/IPv4");
        for (size_t i = 0; i < r->tcp_count; ++i) {
            const PsTcpConnection *c = &r->tcp[i];
            printf("  %-12s %s:%u -> %s:%u\n", ps_tcp_state_name(c->state), c->local_addr, c->local_port,
                   c->remote_addr, c->remote_port);
        }
    }
}

void ps_print_process_json(const PsProcessReport *r) {
    char name[1024], path[PS_MAX_PATH_UTF8], user[1024], integrity[256], arch[256];
    ps_wide_to_utf8(r->image_name, name, sizeof(name));
    ps_wide_to_utf8(r->path, path, sizeof(path));
    ps_wide_to_utf8(r->user, user, sizeof(user));
    ps_wide_to_utf8(r->integrity, integrity, sizeof(integrity));
    ps_wide_to_utf8(r->architecture, arch, sizeof(arch));
    printf("{\"pid\":%lu,\"parent_pid\":%lu,\"image\":", (unsigned long)r->pid, (unsigned long)r->parent_pid);
    ps_json_escape(stdout, name); printf(",\"path\":"); ps_json_escape(stdout, path);
    printf(",\"user\":"); ps_json_escape(stdout, user); printf(",\"integrity\":"); ps_json_escape(stdout, integrity);
    printf(",\"architecture\":"); ps_json_escape(stdout, arch);
    printf(",\"accessible\":%s,\"file\":{\"sha256\":", r->accessible ? "true" : "false");
    ps_json_escape(stdout, r->file.sha256);
    printf(",\"signature\":"); ps_json_escape(stdout, ps_signature_name(r->file.signature));
    printf(",\"score\":%d,\"pe_valid\":%s,\"is_64bit\":%s,\"wx_section\":%s,\"high_entropy_exec\":%s,\"entrypoint_writable\":%s,\"dual_use_api_count\":%u},\"tcp\":[",
           r->file.score, r->file.pe.valid ? "true" : "false", r->file.pe.is_64bit ? "true" : "false",
           r->file.pe.has_wx_section ? "true" : "false",
           r->file.pe.high_entropy_executable_section ? "true" : "false",
           r->file.pe.entrypoint_in_writable_section ? "true" : "false",
           r->file.pe.suspicious_api_count);
    for (size_t i = 0; i < r->tcp_count; ++i) {
        if (i) putchar(',');
        printf("{\"state\":"); ps_json_escape(stdout, ps_tcp_state_name(r->tcp[i].state));
        printf(",\"local\":");
        char ep[160]; snprintf(ep, sizeof(ep), "%s:%u", r->tcp[i].local_addr, r->tcp[i].local_port); ps_json_escape(stdout, ep);
        printf(",\"remote\":"); snprintf(ep, sizeof(ep), "%s:%u", r->tcp[i].remote_addr, r->tcp[i].remote_port); ps_json_escape(stdout, ep);
        putchar('}');
    }
    puts("]}");
}
