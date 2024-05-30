/*
   (c) 2024 Alexey Suslov <alexey.s@ultibot.ru>
   All rights are horse-fucked.
*/

#include "../../structures.h"
#include "ClientProcess.h"

#ifdef __cplusplus
#error "Please, compile as C code only"
#endif

static struct {
    bool shortFormat;
} PluginConfig = {
    .shortFormat = FALSE,
};

static LOGFUNC dolog_3proxy = NULL;
static SOCKET(WINAPI *accept_3proxy)(void *state, SOCKET s, struct sockaddr *addr, int *addrlen);

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

    if ((rv = GetExtendedTcpTable(
             NULL, &tableSize, FALSE, sa->sa_family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0
         )) != ERROR_INSUFFICIENT_BUFFER) {
        return rv;
    }
    if ((data = LocalAlloc(0, tableSize)) == NULL) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    if ((rv = GetExtendedTcpTable(
             data, &tableSize, FALSE, sa->sa_family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0
         )) != NO_ERROR) {
        return rv;
    }

    *pid = 0;
    if (sa->sa_family == AF_INET) {
        SOCKADDR_IN *sin = (SOCKADDR_IN *)sa;
        MIB_TCPTABLE_OWNER_PID *table = data;
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID *row = &table->table[i];
            if (row->dwRemoteAddr == sin->sin_addr.S_un.S_addr &&
                row->dwLocalPort == sin->sin_port) {
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
    char *processName = "[unknown2]"; /* FIXME: will fail on LocalFree() */
    HANDLE hProcess;
    if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)) != INVALID_HANDLE_VALUE) {
        processName = LocalAlloc(0, MAX_PATH);
        GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH);
        CloseHandle(hProcess);
    }
    return processName;
}

#pragma endregion

/* TODO: replace with something more reliable. */
static struct {
    pthread_mutex_t mutex;
    ushort next;
    ushort last;
    ClientProcessSocketInfo cpsi[256]; /* Heuristic. */
} cpsit;

static_assert(countof(cpsit.cpsi) < (1U << sizeof(ushort) * 8), "Too much");

static bool InsertClientProcessRow(SOCKET s_accepted, SOCKADDR *addr) {
    PID pid;
    DWORD rv = GetLocalProcessBySourceSocket(addr, &pid);
    if (rv > 0) {
        DWORD e = GetLastError();
        /* TODO: log as a server: sprintf(ptr, " [error %lu]", e); */
        /* Detailed log format: %C:%c
         *  myinet_ntop(*SAFAMILY(&param->sincr), SAADDR(&param->sincr), (char *)buf + i, 64);
         *  sprintf((char *)buf+i, "%hu", ntohs(*SAPORT(&param->sincr)));
         */
        fprintf(stderr, "error %lu while determining client process\n", e);
        return false;
    } else if (pid == 0) {
        /* Unknown process, probably already exited or remote. */
        /* TODO: distinguish between exited and remote, also take not only 127.0.0.1 into account */
        return false;
    } else {
        bool inserted = FALSE;
        pthread_mutex_lock(&cpsit.mutex);
        for (ushort i = cpsit.next; i < countof(cpsit.cpsi); ++i) {
            ClientProcessSocketInfo *cpsi = &cpsit.cpsi[i];
            if (cpsi->s == 0) {
                cpsi->s = s_accepted;
                cpsi->pid = pid;
                cpsi->pname = GetProcessNameByPid(pid);
                cpsi->pname_short = strrchr(cpsi->pname, '\\') + 1;
                cpsit.next = i + 1;
                if (i >= cpsit.last) {
                    cpsit.last = cpsit.next;
                }
                inserted = TRUE;
                break;
            }
        }
        pthread_mutex_unlock(&cpsit.mutex);
        return inserted;
    }
}

static bool UseClientProcessRow(
    SOCKET clisock, bool (*cb)(ClientProcessSocketInfo *row, const void *data), const void *data
) {
    pthread_mutex_lock(&cpsit.mutex);
    bool success = false;
    for (ushort i = 0; i < cpsit.last; ++i) {
        ClientProcessSocketInfo *cpsi = &cpsit.cpsi[i];
        if (cpsi->s == clisock) {
            success = cb(cpsi, data);
            break;
        }
    }
    pthread_mutex_unlock(&cpsit.mutex);
    return success;
}

static bool ClientProcessRow_LogAndDispose(ClientProcessSocketInfo *cpsi, const void *data) {
    char *ptr = (char *)data;
    if (cpsi->pname != NULL) {
        if (PluginConfig.shortFormat) {
            ptr += sprintf(ptr, " %s", cpsi->pname_short);
        } else {
            ptr += sprintf(ptr, " %s", cpsi->pname);
        }
        LocalFree(cpsi->pname);
    }
    sprintf(ptr, " (%lu)", cpsi->pid);
    cpsi->s = 0; /* Allow to reuse row. */
    ushort i = (ushort)(cpsi - cpsit.cpsi);
    if (i < cpsit.next) {
        cpsit.next = i;
    }
    return true;
}

static bool ClientProcessRow_CheckClientListMatch(ClientProcessSocketInfo *cpsi, const void *data) {
    const ClientProcessACE *cpace = data;
    if (cpace->isShort) {
        return stricmp(cpace->path, cpsi->pname_short) == 0;
    } else {
        return stricmp(cpace->path, cpsi->pname) == 0;
    }
}

static void dolog_override(struct clientparam *param, const unsigned char *buf) {
    if (param->clisock != INVALID_SOCKET) {
        /* This is a hack! We can overflow the buffer (relatively) easily! */
        char *ptr = (char *)buf + strlen((const char *)buf);
        UseClientProcessRow(param->clisock, ClientProcessRow_LogAndDispose, ptr);
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

static struct pluginlink *p_link;
/* Missing in pluginlink. */
static int (*handleredirect)(struct clientparam *param, struct ace *ace);

/* FIXME: temporary solution. */
static struct ClientProcessACEList {
    struct ClientProcessACEList *next;
    ClientProcessACE cpace;
} *aces = NULL;

static int h_clients(int argc, unsigned char **argv) {
    /* Find a linked ACE. */
    struct ace *ace = p_link->conf->acl;
    while (ace && ace->next) {
        ace = ace->next;
    }
    if (ace == NULL || ace->action != ALLOW) {
        fprintf(
            stderr,
            "Client Process plugin error: last ACL entry was not \"allow\" on line %d\n",
            *p_link->linenum
        );
        return 2;
    }

    struct ClientProcessACEList **tmp = &aces;
    while (*tmp) {
        tmp = &(*tmp)->next;
    }
    *tmp = malloc(sizeof(**tmp));
    (*tmp)->next = NULL;
    (*tmp)->cpace.ace = ace;
    /* TODO: support vararg */
    (*tmp)->cpace.path = strdup((char *)argv[1]); /* FIXME: memory leak on unload */
    (*tmp)->cpace.isShort = !strchr((char *)argv[1], '\\');

    return 0;
}

static bool ACLMatchesWithClient(struct ace *ace, struct clientparam *param) {
    const struct ClientProcessACEList *tmp = aces;
    while (tmp) {
        /* FIXME!!! */
        //if (p_link->ACLMatches(ace, param) && p_link->ACLMatches(tmp->cpace.ace, param)) {
        if (ace->linenum == tmp->cpace.ace->linenum) {
            if (UseClientProcessRow(
                    param->clisock, ClientProcessRow_CheckClientListMatch, &tmp->cpace
                )) {
                fprintf(stderr, "matched ace on line %d\n", ace->linenum);
                return true;
            } else {
                return false;
            }
        }
        tmp = tmp->next;
    }
    /* Enable all clients by default. */
    return true;
}

/* For SAISNULL() */
static char *_NULLADDR = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
#define NULLADDR _NULLADDR

/* Copied from checkACL() */
static int ClientProcess_AuthorizeFunc(struct clientparam *param) {
    struct ace *acentry;

    if (param->srv->acl == NULL) {
        return 0;
    }
    for (acentry = param->srv->acl; acentry; acentry = acentry->next) {
        if (p_link->ACLMatches(acentry, param) && ACLMatchesWithClient(acentry, param)) {
            param->nolog = acentry->nolog;
            param->weight = acentry->weight;
            if (acentry->action == REDIRECT) {
                struct ace dup;
                int res = 60, i = 0;

                if (param->operation < 256 && !(param->operation & CONNECT)) {
                    continue;
                }
                if (param->redirected && acentry->chains && SAISNULL(&acentry->chains->addr) &&
                    !*SAPORT(&acentry->chains->addr)) {
                    continue;
                }
                if (param->remsock != INVALID_SOCKET) {
                    return 0;
                }
                for (; i < p_link->conf->parentretries; i++) {
                    dup = *acentry;
                    res = handleredirect(param, &dup);
                    if (!res) {
                        break;
                    }
                    if (param->remsock != INVALID_SOCKET) {
                        param->srv->so._closesocket(param->sostate, param->remsock);
                    }
                    param->remsock = INVALID_SOCKET;
                }
                return res;
            }
            return acentry->action;
        }
    }
    return 3;
}

/* Copied from ipauth() */
static int ClientProcess_AuthenticateFunc(struct clientparam *param) {
    int res;
    unsigned char *username = param->username;
    param->username = NULL;
    res = ClientProcess_AuthorizeFunc(param);
    param->username = username;
    return res;
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

    p_link = link;
    handleredirect =
        (int (*)(struct clientparam *, struct ace *))p_link->findbyname("handleredirect");

    OverrideHandler((void **)&link->conf->logfunc, (void **)&dolog_3proxy, (void *)dolog_override);
    OverrideHandler((void **)&link->so->_accept, (void **)&accept_3proxy, (void *)accept_override);

    static struct commands cmd_clients = {
        .command = "clients",
        .handler = h_clients,
        .minargs = 2,
        .maxargs = 2,
    };
    cmd_clients.next = link->commandhandlers->next;
    link->commandhandlers->next = &cmd_clients;

    static struct auth auth_client_process = {
        .desc = "client_process",
        .authenticate = ClientProcess_AuthenticateFunc,
        .authorize = ClientProcess_AuthorizeFunc,
    };
    auth_client_process.next = link->authfuncs->next;
    link->authfuncs->next = &auth_client_process;

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
