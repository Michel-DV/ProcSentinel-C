#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include "procsentinel/procsentinel.h"

int ps_wide_to_utf8(const wchar_t *src, char *dst, size_t dst_size) {
    int n;
    if (!src || !dst || dst_size == 0) return 0;
    dst[0] = '\0';
    n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, src, -1, dst, (int)dst_size, NULL, NULL);
    if (n == 0) {
        n = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)dst_size, NULL, NULL);
    }
    return n > 0;
}

const char *ps_signature_name(PsSignatureStatus status) {
    switch (status) {
        case PS_SIGNATURE_TRUSTED: return "trusted";
        case PS_SIGNATURE_UNSIGNED: return "unsigned";
        case PS_SIGNATURE_INVALID: return "invalid";
        default: return "unknown";
    }
}

const char *ps_tcp_state_name(uint32_t state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

void ps_json_escape(FILE *fp, const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    fputc('"', fp);
    while (*p) {
        switch (*p) {
            case '"': fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\b': fputs("\\b", fp); break;
            case '\f': fputs("\\f", fp); break;
            case '\n': fputs("\\n", fp); break;
            case '\r': fputs("\\r", fp); break;
            case '\t': fputs("\\t", fp); break;
            default:
                if (*p < 0x20) fprintf(fp, "\\u%04x", *p);
                else fputc(*p, fp);
        }
        ++p;
    }
    fputc('"', fp);
}
