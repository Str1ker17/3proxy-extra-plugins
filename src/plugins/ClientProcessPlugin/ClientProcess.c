/*
   (c) 2024 Alexey Suslov <alexey.s@ultibot.ru>
   All rights are horse-fucked.
*/

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS

#include "../../structures.h"
#include "ClientProcess.h"
#include "../../libs/md4.h"

#ifdef __cplusplus
#error "Please, compile as C code only"
#endif

static struct {
    bool shortFormat;
} PluginConfig = {
    .shortFormat = FALSE,
};

/* Save the pointer in global area for the easier reuse. */
static struct pluginlink *p_link;

/* Original functions that CAN be overridden and present in pluginlink. */
static LOGFUNC dolog_3proxy = NULL;
static SOCKET(WINAPI *accept_3proxy)(void *state, SOCKET s, struct sockaddr *addr, int *addrlen);

/* Original functions that CAN be overridden but NOT present in pluginlink. */
static int (*h_parent_3proxy)(int argc, unsigned char **argv);

/* Original functions that can NOT be overridden and missing in pluginlink. */
static int (*handleredirect)(struct clientparam *param, struct ace *ace);

/* Hax time:
 * * For SAISNULL() */
static char *NULLADDR_ = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
#define NULLADDR NULLADDR_

#pragma region "These functions are supported only on Windows at the moment"

static DWORD GetLocalProcessBySourceSocket(_In_ SOCKADDR *sa, _Out_ _Maybevalid_ PID *pid) {
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
        if (processName != NULL) {
            GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH);
            CloseHandle(hProcess);
        }
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
        char buf[64];
        p_link->myinet_ntop(*SAFAMILY(addr), SAADDR(addr), buf, sizeof(buf));
        dolog(
            "Error %lu while determining client process of %s:%hu", e, buf, be16toh(*SAPORT(addr))
        );
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
#if defined(PLUGIN_DEBUG)
    dolog("cpsit.next=%hu cpsit.last=%hu", cpsit.next, cpsit.last);
#endif
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

/* DONE: catch process as early as possible, just on connection creation.
 * To do it, we need to collect the info inside plugin, in some unordered_map or smth */
static SOCKET(WINAPI *accept_3proxy)(void *state, SOCKET s, struct sockaddr *addr, int *addrlen);

static SOCKET WINAPI accept_override(void *state, SOCKET s, struct sockaddr *addr, int *addrlen) {
    SOCKET s_accepted = accept_3proxy(state, s, addr, addrlen);
    if (s_accepted != INVALID_SOCKET) {
        InsertClientProcessRow(s_accepted, addr);
    }
    return s_accepted;
}

/* FIXME: temporary solution. */
static struct ClientProcessACEList {
    struct ClientProcessACEList *next;
    ClientProcessACE cpace;
} *aces = NULL;

static void ACEHash(struct ace *ace, unsigned char *hash) {
    MD4_CTX ctx;
    MD4Init(&ctx);

    /*
        int action;
        int operation;
        int wdays;
        int weight;
        int nolog;
        struct period *periods;
        struct userlist *users;
        struct iplist *src, *dst;
        struct hostname *dstnames;
        struct portlist *ports;
        struct chain *chains;
    */

#define MD4UpdateLocal(ptr, len) MD4Update(&ctx, (ptr), (len))
#define MD4UpdateField(obj, field)                                                                 \
    MD4UpdateLocal((unsigned char *)&(obj)->field, sizeof((obj)->field))
#define MD4UpdateFieldCStr(obj, field)                                                             \
    do {                                                                                           \
        if ((obj)->field) {                                                                        \
            MD4UpdateLocal(                                                                        \
                (unsigned char *)(obj)->field, (unsigned int)strlen((const char *)(obj)->field)    \
            );                                                                                     \
        }                                                                                          \
    } while (0)

    MD4UpdateField(ace, action);
    MD4UpdateField(ace, operation);
    MD4UpdateField(ace, wdays);
    MD4UpdateField(ace, weight);
    MD4UpdateField(ace, nolog);

    for (struct iplist *ipentry = ace->src; ipentry; ipentry = ipentry->next) {
        MD4UpdateField(ipentry, family);
        MD4UpdateField(ipentry, ip_from);
        MD4UpdateField(ipentry, ip_to);
    }

    for (struct iplist *ipentry = ace->dst; ipentry; ipentry = ipentry->next) {
        MD4UpdateField(ipentry, family);
        MD4UpdateField(ipentry, ip_from);
        MD4UpdateField(ipentry, ip_to);
    }

    for (struct hostname *nameentry = ace->dstnames; nameentry; nameentry = nameentry->next) {
        MD4UpdateField(nameentry, matchtype);
        MD4UpdateFieldCStr(nameentry, name);
    }

    for (struct portlist *portentry = ace->ports; portentry; portentry = portentry->next) {
        MD4UpdateField(portentry, startport);
        MD4UpdateField(portentry, endport);
    }

    for (struct period *periodentry = ace->periods; periodentry; periodentry = periodentry->next) {
        MD4UpdateField(periodentry, fromtime);
        MD4UpdateField(periodentry, totime);
    }

    for (struct userlist *userentry = ace->users; userentry; userentry = userentry->next) {
        MD4UpdateFieldCStr(userentry, user);
    }

    for (struct chain *chainentry = ace->chains; chainentry; chainentry = chainentry->next) {
        /*
            int type;
        #ifndef NOIPV6
            struct sockaddr_in6 addr;
        #else
            struct sockaddr_in addr;
        #endif
            unsigned char * exthost;
            unsigned char * extuser;
            unsigned char * extpass;
            unsigned short weight;
            unsigned short cidr;
        */
        MD4UpdateField(chainentry, addr);
        MD4UpdateFieldCStr(chainentry, exthost);
        MD4UpdateFieldCStr(chainentry, extuser);
        MD4UpdateFieldCStr(chainentry, extpass);
        MD4UpdateField(chainentry, weight);
        MD4UpdateField(chainentry, cidr);
    }

    MD4Final(hash, &ctx);
}

static int h_parent_override(int argc, unsigned char **argv) {
    int rv = h_parent_3proxy(argc, argv);
    if (rv <= 0) {
        struct ace *ace = p_link->conf->acl;
        while (ace && ace->next) {
            ace = ace->next;
        }
        struct ClientProcessACEList *tmp = aces;
        while (tmp && tmp->next) {
            tmp = tmp->next;
        }
        if (tmp) {
            ACEHash(ace, tmp->cpace.hash);
            dolog("recalculated hash for ACE on line %d", *p_link->linenum);
        }
    }
    return rv;
}

static int h_clients(int argc, unsigned char **argv) {
    /* Find a linked ACE. */
    struct ace *ace = p_link->conf->acl;
    while (ace && ace->next) {
        ace = ace->next;
    }
    if (ace == NULL || ace->action != ALLOW) {
        dolog("last ACL entry was not \"allow\" on line %d\n", *p_link->linenum);
        return 2;
    }

    /* TODO: move to something more reliable */
    struct ClientProcessACEList **tmp = &aces;
    while (*tmp) {
        tmp = &(*tmp)->next;
    }
    *tmp = malloc(sizeof(**tmp));
    if (*tmp == NULL) {
        return 1;
    }
    (*tmp)->next = NULL;
    ACEHash(ace, (*tmp)->cpace.hash);
    /* TODO: support vararg */
    (*tmp)->cpace.path = strdup((char *)argv[1]); /* FIXME: memory leak on unload */
    (*tmp)->cpace.isShort = (strchr((char *)argv[1], '\\') == NULL);

    return 0;
}

static bool ACLMatchesWithClient(struct ace *ace, struct clientparam *param) {
    const struct ClientProcessACEList *tmp = aces;
    unsigned char hash[16];
    ACEHash(ace, hash);
    while (tmp) {
        /* FIXME!!! */
        if (memcmp(hash, tmp->cpace.hash, sizeof(tmp->cpace.hash)) == 0) {
            if (UseClientProcessRow(
                    param->clisock, ClientProcessRow_CheckClientListMatch, &tmp->cpace
                )) {
#if defined(PLUGIN_DEBUG)
                dolog("matched ACL entry on line %d extended by client list", ace->linenum);
#endif
                return true;
            } else {
#if defined(PLUGIN_DEBUG)
                dolog("matched ACL entry on line %d but not the client list", ace->linenum);
#endif
                return false;
            }
        }
        tmp = tmp->next;
    }
    /* Enable all clients by default. */
#if defined(PLUGIN_DEBUG)
    dolog("matched ACL entry on line %d and the client list is empty", ace->linenum);
#endif
    return true;
}

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

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "format=short") == 0) {
            PluginConfig.shortFormat = true;
            dolog("Using short format for logs");
        } else if (strcmp(argv[i], "format=long") == 0) {
            PluginConfig.shortFormat = false;
        } else {
            dolog("The option '%s' is not supported. Exiting", argv[i]);
            return 1; /* Non-recoverable error. */
        }
    }

    OverrideHandler((void **)&link->conf->logfunc, (void **)&dolog_3proxy, (void *)dolog_override);
    OverrideHandler((void **)&link->so->_accept, (void **)&accept_3proxy, (void *)accept_override);

    handleredirect =
        (int (*)(struct clientparam *, struct ace *))p_link->findbyname("handleredirect");

    static struct commands cmd_clients = {
        .command = "clients",
        .handler = h_clients,
        .minargs = 2, /* Minimum number, counting command itself (so >= 1) that command requires. */
        .maxargs = 2, /* Maximum number that command supports, 0 means infinity. */
    };
    cmd_clients.next = link->commandhandlers->next;
    link->commandhandlers->next = &cmd_clients;

    /* Intercept "parent" handler as it alters the ACE and this leads to hash mismatch. */
    for (struct commands *cmd = link->commandhandlers; cmd; cmd = cmd->next) {
        if (strcmp(cmd->command, "parent") == 0) {
            h_parent_3proxy = cmd->handler;
            cmd->handler = h_parent_override;
            break;
        }
    }

    /* TODO: instead of adding a completely new auth method,
     * intercept all .authorize functions in existing auth methods
     * (this may be non-working though) */
    static struct auth auth_client_process = {
        .desc = "client_process",
        .authenticate = ClientProcess_AuthenticateFunc,
        .authorize = ClientProcess_AuthorizeFunc,
    };
    auth_client_process.next = link->authfuncs->next;
    link->authfuncs->next = &auth_client_process;

    return 0;
}

static void PluginConstructor(void) { pthread_mutex_init(&cpsit.mutex, NULL); }

static void PluginDestructor(void) { pthread_mutex_destroy(&cpsit.mutex); }

BOOL WINAPI DllMain(HANDLE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH: {
            PluginConstructor();
            return TRUE;
        }
        case DLL_PROCESS_DETACH: {
            PluginDestructor();
            return TRUE;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default: {
            return TRUE;
        }
    }
}
