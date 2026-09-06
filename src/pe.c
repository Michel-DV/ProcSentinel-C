#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "procsentinel/procsentinel.h"

static int bounds(size_t off, size_t need, size_t size) {
    return off <= size && need <= size - off;
}

static const unsigned char *rva_ptr(const unsigned char *buf, size_t size, const IMAGE_SECTION_HEADER *sections,
                                    size_t section_count, uint32_t rva, size_t need) {
    for (size_t i = 0; i < section_count; ++i) {
        uint32_t va = sections[i].VirtualAddress;
        uint32_t span = sections[i].Misc.VirtualSize > sections[i].SizeOfRawData ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        uint64_t end = (uint64_t)va + (uint64_t)span;
        if ((uint64_t)rva >= va && (uint64_t)rva < end) {
            size_t off = (size_t)sections[i].PointerToRawData + (size_t)(rva - va);
            if (bounds(off, need, size)) return buf + off;
            return NULL;
        }
    }
    if (bounds(rva, need, size)) return buf + rva;
    return NULL;
}

static void copy_cstr(char *dst, size_t dst_size, const unsigned char *p, const unsigned char *end) {
    size_t i = 0;
    if (!dst || dst_size == 0) return;
    while (p < end && *p && i + 1 < dst_size) {
        unsigned char ch = *p++;
        dst[i++] = (ch >= 0x20 && ch <= 0x7e) ? (char)ch : '?';
    }
    dst[i] = '\0';
}

double ps_entropy(const unsigned char *data, size_t len) {
    uint64_t counts[256] = {0};
    double e = 0.0;
    if (!data || len == 0) return 0.0;
    for (size_t i = 0; i < len; ++i) counts[data[i]]++;
    for (size_t i = 0; i < 256; ++i) {
        if (counts[i]) {
            double p = (double)counts[i] / (double)len;
            e -= p * (log(p) / log(2.0));
        }
    }
    return e;
}

static int suspicious_api(const char *name) {
    static const char *apis[] = {
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "OpenProcess", "QueueUserAPC", "SetThreadContext", "ResumeThread"
    };
    for (size_t i = 0; i < sizeof(apis) / sizeof(apis[0]); ++i) {
        if (_stricmp(name, apis[i]) == 0) return 1;
    }
    return 0;
}

static void parse_imports(const unsigned char *buf, size_t size, const IMAGE_SECTION_HEADER *sections,
                          size_t section_count, uint32_t import_rva, int is64, PsPeInfo *out) {
    const IMAGE_IMPORT_DESCRIPTOR *desc;
    size_t guard = 0;
    if (!import_rva) return;
    while (guard < 256) {
        uint32_t desc_rva = import_rva + (uint32_t)(guard * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        desc = (const IMAGE_IMPORT_DESCRIPTOR *)rva_ptr(buf, size, sections, section_count, desc_rva, sizeof(*desc));
        if (!desc || (!desc->Name && !desc->FirstThunk && !desc->OriginalFirstThunk)) break;
        guard++;
        const unsigned char *dllp = rva_ptr(buf, size, sections, section_count, desc->Name, 1);
        char dll[64] = "?";
        uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        if (dllp) copy_cstr(dll, sizeof(dll), dllp, buf + size);

        if (thunk_rva) {
            size_t index = 0;
            while (index < 4096 && out->import_count < PS_MAX_IMPORTS) {
                uint64_t raw = 0;
                const unsigned char *tp = rva_ptr(buf, size, sections, section_count,
                                                  thunk_rva + (uint32_t)(index * (is64 ? 8 : 4)), is64 ? 8 : 4);
                if (!tp) break;
                if (is64) memcpy(&raw, tp, 8); else { uint32_t v; memcpy(&v, tp, 4); raw = v; }
                if (!raw) break;

                if ((is64 && (raw & IMAGE_ORDINAL_FLAG64)) || (!is64 && (raw & IMAGE_ORDINAL_FLAG32))) {
                    PsImportInfo *ii = &out->imports[out->import_count++];
                    strncpy(ii->dll, dll, sizeof(ii->dll) - 1);
                    ii->dll[sizeof(ii->dll) - 1] = '\0';
                    strcpy(ii->symbol, "<ordinal>");
                } else {
                    uint32_t name_rva = (uint32_t)(raw & 0xffffffffu);
                    const unsigned char *np = rva_ptr(buf, size, sections, section_count, name_rva, 3);
                    if (!np) break;
                    PsImportInfo *ii = &out->imports[out->import_count++];
                    strncpy(ii->dll, dll, sizeof(ii->dll) - 1);
                    ii->dll[sizeof(ii->dll) - 1] = '\0';
                    copy_cstr(ii->symbol, sizeof(ii->symbol), np + 2, buf + size);
                    if (suspicious_api(ii->symbol)) out->suspicious_api_count++;
                }
                index++;
            }
        }
    }
}

int ps_analyze_pe_file(const wchar_t *path, PsPeInfo *out) {
    FILE *fp = NULL;
    unsigned char *buf = NULL;
    size_t size = 0;
    int ok = 0;
    IMAGE_DOS_HEADER *dos;
    IMAGE_FILE_HEADER *fh;
    IMAGE_SECTION_HEADER *sections;
    uint32_t import_rva = 0;
    uint16_t magic;
    size_t nt_off, opt_off, sec_off;

    if (!path || !out) return 0;
    ZeroMemory(out, sizeof(*out));

    fp = _wfopen(path, L"rb");
    if (!fp) goto done;
    if (_fseeki64(fp, 0, SEEK_END) != 0) goto done;
    __int64 sz = _ftelli64(fp);
    if (sz < (long long)sizeof(IMAGE_DOS_HEADER) || sz > 512LL * 1024 * 1024) goto done;
    size = (size_t)sz;
    if (_fseeki64(fp, 0, SEEK_SET) != 0) goto done;
    buf = (unsigned char *)malloc(size);
    if (!buf) goto done;
    if (fread(buf, 1, size, fp) != size) goto done;

    dos = (IMAGE_DOS_HEADER *)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) goto done;
    nt_off = (size_t)dos->e_lfanew;
    if (!bounds(nt_off, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), size)) goto done;
    if (*(DWORD *)(buf + nt_off) != IMAGE_NT_SIGNATURE) goto done;

    fh = (IMAGE_FILE_HEADER *)(buf + nt_off + sizeof(DWORD));
    opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!bounds(opt_off, fh->SizeOfOptionalHeader, size) || fh->SizeOfOptionalHeader < sizeof(uint16_t)) goto done;
    memcpy(&magic, buf + opt_off, sizeof(magic));

    out->machine = fh->Machine;
    out->timestamp = fh->TimeDateStamp;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const IMAGE_OPTIONAL_HEADER64 *oh = (const IMAGE_OPTIONAL_HEADER64 *)(buf + opt_off);
        if (fh->SizeOfOptionalHeader < sizeof(*oh)) goto done;
        out->is_64bit = 1;
        out->entry_rva = oh->AddressOfEntryPoint;
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        const IMAGE_OPTIONAL_HEADER32 *oh = (const IMAGE_OPTIONAL_HEADER32 *)(buf + opt_off);
        if (fh->SizeOfOptionalHeader < sizeof(*oh)) goto done;
        out->is_64bit = 0;
        out->entry_rva = oh->AddressOfEntryPoint;
        if (oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            import_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else goto done;

    sec_off = opt_off + fh->SizeOfOptionalHeader;
    if (!bounds(sec_off, (size_t)fh->NumberOfSections * sizeof(IMAGE_SECTION_HEADER), size)) goto done;
    sections = (IMAGE_SECTION_HEADER *)(buf + sec_off);
    out->section_count = fh->NumberOfSections < PS_MAX_SECTIONS ? fh->NumberOfSections : PS_MAX_SECTIONS;

    for (size_t i = 0; i < out->section_count; ++i) {
        PsSectionInfo *si = &out->sections[i];
        uint32_t va = sections[i].VirtualAddress;
        uint32_t span = sections[i].Misc.VirtualSize > sections[i].SizeOfRawData ? sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
        memcpy(si->name, sections[i].Name, 8);
        si->name[8] = '\0';
        for (size_t n = 0; n < 8 && si->name[n]; ++n) {
            unsigned char ch = (unsigned char)si->name[n];
            if (ch < 0x20 || ch > 0x7e) si->name[n] = '?';
        }
        si->virtual_address = va;
        si->virtual_size = sections[i].Misc.VirtualSize;
        si->raw_size = sections[i].SizeOfRawData;
        si->characteristics = sections[i].Characteristics;
        si->contains_entrypoint = (uint64_t)out->entry_rva >= va && (uint64_t)out->entry_rva < (uint64_t)va + (uint64_t)span;
        if (sections[i].SizeOfRawData && bounds(sections[i].PointerToRawData, sections[i].SizeOfRawData, size))
            si->entropy = ps_entropy(buf + sections[i].PointerToRawData, sections[i].SizeOfRawData);

        if ((si->characteristics & IMAGE_SCN_MEM_EXECUTE) && (si->characteristics & IMAGE_SCN_MEM_WRITE)) out->has_wx_section = 1;
        if ((si->characteristics & IMAGE_SCN_MEM_EXECUTE) && si->entropy >= 7.20) out->high_entropy_executable_section = 1;
        if (si->contains_entrypoint && (si->characteristics & IMAGE_SCN_MEM_WRITE)) out->entrypoint_in_writable_section = 1;
    }

    parse_imports(buf, size, sections, fh->NumberOfSections, import_rva, out->is_64bit, out);
    out->valid = 1;
    ok = 1;

done:
    if (buf) free(buf);
    if (fp) fclose(fp);
    return ok;
}
