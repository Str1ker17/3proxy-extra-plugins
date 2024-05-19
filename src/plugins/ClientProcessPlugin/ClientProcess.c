/*
   (c) 2024 Alexey Suslov <alexey.s@ultibot.ru>
*/

#include "../../structures.h"
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
#include <psapi.h>
typedef DWORD PID;
#else
#error "Non-Windows systems are not supported. Please add support!"
#endif

typedef unsigned short ushort;

#define countof(a) (sizeof(a) / sizeof((a)[0]))
#define htobe16(x) ((((x)&0xffU) << 8) | ((x) >> 8))
#define be16toh htobe16

#ifdef __cplusplus
#error "Please, compile as C code only"
#endif

static struct {
    bool shortFormat;
} PluginConfig = {
    .shortFormat = FALSE,
};

typedef struct {
    SOCKET s;
    PID pid;
    char *pname;
} ClientProcessSocketInfo;

#pragma region "These functions are supported only on Windows at the moment"

static DWORD GetLocalProcessBySourceSocket(_In_ SOCKADDR *sa, _Out_ PID *pid) {
    VOID *data;
    DWORD tableSize = 0;
    DWORD rv;

    /* For a reason it's still a Big Endian. Oh well. */
    switch (sa->sa_family) {
        case AF_INET:
        case AF_INET6:
            break;
        default:
            return ERROR_INVALID_PARAMETER;
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
    if (sa->sa_family == AF_INET) {
        SOCKADDR_IN *sin = (SOCKADDR_IN *)sa;
        MIB_TCPTABLE_OWNER_PID *table = data;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            if (row->dwRemoteAddr == sin->sin_addr.S_un.S_addr && row->dwLocalPort == sin->sin_port) {
                *pid = row->dwOwningPid;
                break;
            }
        }
    } else if (sa->sa_family == AF_INET6) {
        SOCKADDR_IN6 *sin6 = (SOCKADDR_IN6 *)sa;
        MIB_TCP6TABLE_OWNER_PID *table = data;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_TCP6ROW_OWNER_PID *row = &table->table[i];
            if (memcmp(row->ucRemoteAddr, sin6->sin6_addr.u.Byte, sizeof(row->ucRemoteAddr)) == 0 &&
                row->dwLocalPort == sin6->sin6_port) {
                *pid = row->dwOwningPid;
                break;
            }
        }
    }

    LocalFree(data);
    return rv;
}

static char *GetProcessNameByPid(PID pid) {
    char *processName = "[unknown2]";
    HANDLE hProcess;
    if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)) != INVALID_HANDLE_VALUE) {
        processName = LocalAlloc(0, MAX_PATH);
        GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH);
        CloseHandle(hProcess);
    }
    return processName;
}

#pragma endregion

static struct {
    pthread_mutex_t mutex;
    ushort next;
    ushort last;
    ClientProcessSocketInfo cpsi[256]; /* Heuristic. */
} cpsit;
static_assert(countof(cpsit.cpsi) < (1 << sizeof(ushort) * 8), "Too much");

static bool InsertClientProcessRow(SOCKET s_accepted, SOCKADDR *addr) {
    PID pid;
    DWORD rv = GetLocalProcessBySourceSocket(addr, &pid);
    if (rv > 0) {
        DWORD e = GetLastError();
        /* TODO: log as a server: sprintf(ptr, " [error %lu]", e); */
        fprintf(stdout, "error %lu while determining client process\n", e);
        return false;
    } else if (pid == 0) {
        /* Unknown process, probably already exited or remote. */
        /* TODO: distinguish between exited and remote, also take not only 127.0.0.1 into account */
    } else {
        bool inserted = FALSE;
        pthread_mutex_lock(&cpsit.mutex);
        for (ushort i = cpsit.next; i < countof(cpsit.cpsi); ++i) {
            ClientProcessSocketInfo *cpsi = &cpsit.cpsi[i];
            if (cpsi->s == 0) {
                cpsi->s = s_accepted;
                cpsi->pid = pid;
                cpsi->pname = GetProcessNameByPid(pid);
                cpsit.next = i + 1;
                if (cpsit.last < i)
                    cpsit.last = cpsit.next;
                inserted = TRUE;
            }
        }
        pthread_mutex_unlock(&cpsit.mutex);
        return inserted;
    }
    return false;
}

static bool TakeClientProcessRow(SOCKET clisock, char *ptr) {
    pthread_mutex_lock(&cpsit.mutex);
    bool success = false;
    for (ushort i = 0; i < cpsit.last; ++i) {
        ClientProcessSocketInfo *cpsi = &cpsit.cpsi[i];
        if (cpsi->s == clisock) {
            if (cpsi->pname != NULL) {
                if (PluginConfig.shortFormat) {
                    char *shrt;
                    if ((shrt = strrchr(cpsit.cpsi[i].pname, '\\')) == NULL) {
                        shrt = cpsit.cpsi[i].pname;
                    } else {
                        shrt += 1;
                    }
                    ptr += sprintf(ptr, " %s", shrt);
                } else {
                    ptr += sprintf(ptr, " %s", cpsit.cpsi[i].pname);
                }
                LocalFree(cpsit.cpsi[i].pname);
            }
            sprintf(ptr, " (%lu)", cpsi->pid);
            cpsi->s = 0; /* Allow to reuse row. */
            if (cpsit.next > i) {
                cpsit.next = i;
            }
            success = true;
            break;
        }
    }
    pthread_mutex_unlock(&cpsit.mutex);
    return success;
}

static LOGFUNC dolog_3proxy = NULL;
static void dolog_override(struct clientparam *param, const unsigned char *buf) {
    if (param->clisock != INVALID_SOCKET) {
        /* This is a hack! We can overflow the buffer (relatively) easily! */
        char *ptr = (char *)buf + strlen((const char *)buf);
        TakeClientProcessRow(param->clisock, ptr);
    }
    dolog_3proxy(param, buf);
}

/* TODO: catch process early, just on connection creation.
 * but to do it, we need to collect the info inside plugin, in some unordered_map or smth */
static SOCKET(WINAPI *accept_3proxy)(void *state, SOCKET s, struct sockaddr *addr, int *addrlen);
static SOCKET WINAPI accept_override(void *state, SOCKET s, struct sockaddr *addr, int *addrlen) {
    SOCKET s_accepted = accept_3proxy(state, s, addr, addrlen);
    if (s_accepted != INVALID_SOCKET) {
        InsertClientProcessRow(s_accepted, addr);
    }
    return s_accepted;
}

static void OverrideHandler(void **handler, void **handler_original, void *overrider) {
    /* Allow 'monitor' command to work: save only original 3proxy handler */
    if (*handler_original == NULL) {
        *handler_original = *handler;
    }
    /* Allow 'monitor' command to work: load new implementation on DLL change */
    *handler = overrider;
}

PLUGINAPI int PLUGINCALL Initialize(struct pluginlink *link, int argc, char **argv) {
    /* We need to intercept the following functions:
     *    For basic functionality:
     *          pluginlink->conf->logfunc;
     *          pluginlink->so->_accept;
     *    For extended functionality, i.e. ACL for Client Processes:
     *          pluginlink->ACLMatches;
     *          pluginlink->commandhandlers->command == "allow"
     *          pluginlink->commandhandlers->command == "deny"
     */

    OverrideHandler((void **)&link->conf->logfunc, (void **)&dolog_3proxy, (void *)dolog_override);
    OverrideHandler((void **)&link->so->_accept, (void **)&accept_3proxy, (void *)accept_override);

    return 0;
}

BOOL WINAPI DllMain(HANDLE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH: {
            pthread_mutex_init(&cpsit.mutex, NULL);
            return TRUE;
        }
        case DLL_PROCESS_DETACH: {
            pthread_mutex_destroy(&cpsit.mutex);
            return TRUE;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default: {
            return TRUE;
        }
    }
}
