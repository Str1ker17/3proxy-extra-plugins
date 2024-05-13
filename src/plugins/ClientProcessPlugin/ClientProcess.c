/*
   (c) 2024 Alexey Suslov <alexey.s@ultibot.ru>
*/

#include "../../structures.h"
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
//#include <tlhelp32.h>
//#include <unordered_map>

#define htobe16(x) ((((x)&0xffU) << 8) | ((x) >> 8))
#define be16toh htobe16

#ifdef __cplusplus
extern "C" {
#endif

static DWORD GetLocalProcessBySourceSocket(_In_ SOCKADDR *sa, _Out_ DWORD *pid) {
    MIB_TCPTABLE_OWNER_PID *data;
    DWORD tableSize = 0;
    DWORD rv;

    /* For a reason it's still a Big Endian. Oh well. */
    USHORT port;
    switch (sa->sa_family) {
        case AF_INET: port = ((SOCKADDR_IN*)sa)->sin_port; break;
        default: return ERROR_INVALID_PARAMETER;
    }

    if ((rv = GetExtendedTcpTable(NULL, &tableSize, FALSE, sa->sa_family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)) !=
        ERROR_INSUFFICIENT_BUFFER) {
        return rv;
    }
    if ((data = LocalAlloc(0, tableSize)) == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if ((rv = GetExtendedTcpTable(data, &tableSize, FALSE, sa->sa_family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)) != NO_ERROR) {
        return rv;
    }

    *pid = 0;
    for (DWORD i = 0; i < data->dwNumEntries; ++i) {
        MIB_TCPROW_OWNER_PID *row = &data->table[i];
        if (row->dwLocalAddr == ((SOCKADDR_IN*)sa)->sin_addr.S_un.S_addr && row->dwLocalPort == port) {
            *pid = row->dwOwningPid;
            break;
        }
    }

    LocalFree(data);
    return rv;
}

static char *GetProcessNameByPid(DWORD pid) {
    CHAR *processName = "[unknown2]";
    HANDLE hProcess;
    if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)) != INVALID_HANDLE_VALUE) {
        processName = LocalAlloc(0, MAX_PATH);
        GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH);
        CloseHandle(hProcess);
    }
    return processName;
}

static LOGFUNC dolog_3proxy;
static void dolog_override(struct clientparam *param, const unsigned char *buf) {
    if (param->clisock != INVALID_SOCKET) {
        /* This is a hack! We can overflow the buffer (relatively) easy! */
        char *ptr = (char *)buf + strlen((const char *)buf);
        SOCKADDR sa;
        int namelen = sizeof(sa);
        param->srv->so._getpeername(NULL, param->clisock, &sa, &namelen);
        DWORD pid;
        DWORD rv = GetLocalProcessBySourceSocket(&sa, &pid);
        if (rv > 0) {
            DWORD e = GetLastError();
            sprintf(ptr, " [error %lu]", e);
        } else if (pid == 0) {
            sprintf(ptr, " [unknown]");
        } else {
            CHAR *pname = GetProcessNameByPid(pid);
            sprintf(ptr, " %s", pname);
            LocalFree(pname);
        }
    }
    dolog_3proxy(param, buf);
}

/* TODO: catch process early, just on connection creation.
 * but to do it, we need to collect the info inside plugin, in some unordered_map or smth */
#if 0
#ifdef __cplusplus
static std::unordered_map<struct clientparam *, DWORD> procs();
#endif
typedef SOCKET(WINAPI *_accept_fn)(void *state, SOCKET s, struct sockaddr *addr, int *addrlen);
static _accept_fn _accept_fn_ptr;
static SOCKET WINAPI _accept(void *state, SOCKET s, struct sockaddr *addr, int *addrlen) {
    SOCKET sa = _accept_fn_ptr(state, s, addr, addrlen);
    if (sa != INVALID_SOCKET) {
        BOOL doLookup = FALSE;
        switch (addr->sa_family) {
            case AF_INET: {
                SOCKADDR_IN *a4 = ((SOCKADDR_IN *)addr);
                if (a4->sin_addr.S_un.S_un_b.s_b1 == 127) {
                    doLookup = TRUE;
                }
            }
        }
        if (doLookup) {
            printf("accepted local connection from port %hu\n", htobe16(((SOCKADDR_IN *)addr)->sin_port));
            //_pid = GetLocalProcessBySourceSocket(((SOCKADDR_IN *)addr));
        }
    }
    return sa;
}
#endif

PLUGINAPI int PLUGINCALL Initialize(struct pluginlink *link, int argc, char **argv) {
    /* We need to intercept the following functions:
     *    For basic functionality:
     *          pluginlink->conf->logfunc;
     *          pluginlink->so->_accept; (?)
     *    For extended functionality, i.e. ACL for Client Processes:
     *          pluginlink->ACLMatches;
     *          pluginlink->commandhandlers->command == "allow"
     *          pluginlink->commandhandlers->command == "deny"
     */
    dolog_3proxy = link->conf->logfunc;
    link->conf->logfunc = dolog_override;

    //_accept_fn_ptr = link->so->_accept;
    // link->so->_accept = _accept;
    return 0;
}

#ifdef __cplusplus
}
#endif
