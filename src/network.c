#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <string.h>
#include "procsentinel/procsentinel.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

int ps_collect_tcp4_for_pid(DWORD pid, PsTcpConnection *out, size_t capacity, size_t *count) {
    DWORD size = 0;
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD rc;
    size_t n = 0;

    if (count) *count = 0;
    rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER) return 0;
    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return 0;
    rc = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR) { free(table); return 0; }

    for (DWORD i = 0; i < table->dwNumEntries && n < capacity; ++i) {
        MIB_TCPROW_OWNER_PID *row = &table->table[i];
        struct in_addr la, ra;
        char local[INET_ADDRSTRLEN] = "0.0.0.0";
        char remote[INET_ADDRSTRLEN] = "0.0.0.0";
        if (row->dwOwningPid != pid) continue;
        la.S_un.S_addr = row->dwLocalAddr;
        ra.S_un.S_addr = row->dwRemoteAddr;
        InetNtopA(AF_INET, &la, local, sizeof(local));
        InetNtopA(AF_INET, &ra, remote, sizeof(remote));
        strncpy(out[n].local_addr, local, sizeof(out[n].local_addr) - 1);
        strncpy(out[n].remote_addr, remote, sizeof(out[n].remote_addr) - 1);
        out[n].local_addr[sizeof(out[n].local_addr) - 1] = '\0';
        out[n].remote_addr[sizeof(out[n].remote_addr) - 1] = '\0';
        out[n].local_port = ntohs((u_short)row->dwLocalPort);
        out[n].remote_port = ntohs((u_short)row->dwRemotePort);
        out[n].state = row->dwState;
        n++;
    }
    free(table);
    if (count) *count = n;
    return 1;
}

int ps_collect_tcp4_for_processes(PsProcessReport *items, size_t item_count) {
    DWORD size = 0;
    PMIB_TCPTABLE_OWNER_PID table = NULL;
    DWORD rc;
    if (!items && item_count) return 0;
    for (size_t i = 0; i < item_count; ++i) items[i].tcp_count = 0;

    rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER) return 0;
    table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return 0;
    rc = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != NO_ERROR) { free(table); return 0; }

    for (DWORD r = 0; r < table->dwNumEntries; ++r) {
        MIB_TCPROW_OWNER_PID *row = &table->table[r];
        for (size_t i = 0; i < item_count; ++i) {
            PsProcessReport *pr = &items[i];
            if (pr->pid != row->dwOwningPid || pr->tcp_count >= PS_MAX_TCP) continue;
            PsTcpConnection *c = &pr->tcp[pr->tcp_count++];
            struct in_addr la, ra;
            la.S_un.S_addr = row->dwLocalAddr;
            ra.S_un.S_addr = row->dwRemoteAddr;
            if (!InetNtopA(AF_INET, &la, c->local_addr, sizeof(c->local_addr))) strcpy(c->local_addr, "0.0.0.0");
            if (!InetNtopA(AF_INET, &ra, c->remote_addr, sizeof(c->remote_addr))) strcpy(c->remote_addr, "0.0.0.0");
            c->local_port = ntohs((u_short)row->dwLocalPort);
            c->remote_port = ntohs((u_short)row->dwRemotePort);
            c->state = row->dwState;
            break;
        }
    }
    free(table);
    return 1;
}
