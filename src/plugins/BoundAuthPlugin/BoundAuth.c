/*
   (c) 2025 Alexey Suslov <alexey.s@ultibot.ru>
   All rights are horse-fucked.
*/

#ifdef __cplusplus
#error "Please, compile as C code only"
#endif

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ < 199901L)
#error "Please, compile as C99 code"
#endif

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS

#undef PLUGIN_DEBUG

enum {
    RETURN_SUCCESS = 0,
    RETURN_INTERNAL_ERROR = 1,
    RETURN_INVALID_INPUT = 2,
    RETURN_PROCESSING_ERROR = 3,
};

enum {
    AUTH_SUCCESSFUL = 0,
    AUTH_DENIED = 1,
    AUTH_NO_MATCHING_RULE = 3,
    AUTH_NO_USERNAME_PRESENT = 4,
    AUTH_NO_USERNAME_FOUND = 5,
    AUTH_WRONG_PASSWORD = 6,
};

#include "../../structures.h"
#include <stdbool.h>
#include <malloc.h>
#include <stdlib.h>

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

#define countof(a) (sizeof(a) / sizeof((a)[0]))
#define static_assert(expr) _Static_assert(expr, __FILE__ ":" STRINGIFY(__LINE__))

#pragma warning(push)
#pragma warning(disable: 4152)
#pragma warning(disable: 4242)
#pragma warning(disable: 4244)
#pragma warning(disable: 4267)
#include "picohash.h"
#pragma warning(pop)

#define ALPHABET_BASE32_LOWER "abcdefghijklmnopqrstuvwxyz234567"
#define ALPHABET_BASE32_UPPER "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
#define ALPHABET_BASE64 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

/* Сложно сделать идеальный однозначный алфавит. Фак. */
#define ALPHABET_CONVENIENT "23456789acdefgjkmnpqsrtuvxyz-_=+"

#define ALPHABET_DEFAULT ALPHABET_BASE32_LOWER
#define ALPHABET_DEFAULT_SIZE (sizeof(ALPHABET_DEFAULT) - 1)

#ifdef _WIN32
#define PATH_DELIMITER '\\'
#define strcasecmp stricmp
#else
#define PATH_DELIMITER '/'
#endif

#define log_err(fmt, ...)                                                                          \
    fprintf(stderr, "[x] %s::%s:" STRINGIFY(__LINE__) " | " fmt "\n", (strrchr(__FILE__, PATH_DELIMITER) ? strrchr(__FILE__, PATH_DELIMITER) + 1 : __FILE__), __FUNCTION__, ##__VA_ARGS__)
#define log_err_config(plugin_link, fmt, ...)                                                       \
    log_err("config line %d: " fmt, *((plugin_link)->linenum), ##__VA_ARGS__)

typedef struct {
    char *data;
    size_t len;
} str_t;

#define STR_EXPR(_val) ((str_t){ .data = (char *)(_val), .len = strlen(_val) })
#define STR_EXPRC(_val) ((str_t){ .data = (_val), .len = sizeof(_val) - 1 })

/* Save the pointer in global area for the easier reuse. */
static struct pluginlink *p_link;

static struct {
    str_t alphabet;
    str_t secret;
    uint8_t len;
    bool initialized;
} PluginConfig = {
    .alphabet = { ALPHABET_DEFAULT, ALPHABET_DEFAULT_SIZE },
    .secret = { NULL, 0 },
    .len = 8,
    .initialized = false,
};

static void StringizeBytes(const uint8_t *data, const size_t len, const char *alphabet, const size_t alphabet_len, char *str, const size_t str_len) {
    size_t currByte = 0;
    size_t currByteBit = 0;

    /* Auto-detect base. */
    uint8_t bitsPerChar = 0;
    for (size_t al = alphabet_len - 1; al; al >>= 1) { ++bitsPerChar; }
    assert(bitsPerChar <= 8);
    uint8_t shift = 8U - bitsPerChar;
    uint8_t mask = (uint8_t)((1U << bitsPerChar) - 1U);

    char *ptr = str;
    for (size_t pos = 0; (currByte < len) && ((size_t)(ptr - str) < str_len); ++pos) {
        /* From 0x63 => 0b01100011 take 0b01100 first and 011 + next byte last */
        uint8_t val = ((data[currByte] << currByteBit) >> shift) & mask;
        currByteBit += bitsPerChar;
        if (currByteBit >= 8) {
            ++currByte;
            currByteBit -= 8;
            if (currByte < len) {
                val |= (data[currByte] >> (8 - currByteBit));
            }
        }
        *ptr++ = alphabet[val];
    }
}

typedef
#ifdef NOIPV6
struct sockaddr_in
#else
struct sockaddr_in6
#endif
sockaddr_used;

/**
 * Two-factor HMAC is supported, if `secret' is set in server configs. This is completely optional.
 *   pw_single = HMAC(pw_private, ip)
 *   pw_double = HMAC(secret, pw_single)
 * This scheme can be more strong in some scenarios. Of course, that's a bad idea to leak any `password' or `secret'.
 * @param [in] pw_private 
 * @param [in] addr 
 * @param [out] pw_public Stringized `pw_signle' or `pw_double', depending on config.
 */
static void PasswordBoundize(const char *pw_private, sockaddr_used *addr, char *pw_public) {
    uint8_t pw_single[PICOHASH_SHA256_DIGEST_LENGTH];
    uint8_t pw_double[PICOHASH_SHA256_DIGEST_LENGTH];
    uint8_t *pw_hmac = pw_single;

    picohash_ctx_t ctx;
    picohash_init_hmac(&ctx, picohash_init_sha256, pw_private, strlen(pw_private));
    picohash_update(&ctx, SAADDR(addr), SAADDRLEN(addr));
    picohash_final(&ctx, pw_single);

    if (PluginConfig.secret.data != NULL) {
        picohash_init_hmac(&ctx, picohash_init_sha256, PluginConfig.secret.data, PluginConfig.secret.len);
        picohash_update(&ctx, pw_single, sizeof(pw_single));
        picohash_final(&ctx, pw_double);
        pw_hmac = pw_double;
    }

    StringizeBytes(pw_hmac, sizeof(pw_single), PluginConfig.alphabet.data, PluginConfig.alphabet.len, pw_public, PluginConfig.len);
}

static bool PasswordCheck(const char *pw_public, sockaddr_used *addr, const char *pw_private) {
    if (strlen(pw_public) != PluginConfig.len) {
        return false;
    }
    char *token = alloca(PluginConfig.len + 1);
#if defined(PLUGIN_DEBUG)
    token[PluginConfig.passwordLen] = '\0';
#endif
    PasswordBoundize(pw_private, addr, token);
    if (memcmp(token, pw_public, PluginConfig.len) != 0) {
        return false;
    }
    return true;
}

/* Mostly like strongauth() but use HMAC(SHA256(password), ipaddr) as a password. */
static int BoundAuth_AuthenticateFunc(struct clientparam *param) {
    if (param->username == NULL)
        return AUTH_NO_USERNAME_PRESENT;
    int rc = AUTH_NO_USERNAME_FOUND;
    /* FIXME: add lock over conf->pwl!! */
    for (struct passwords *pwl = p_link->conf->pwl; pwl; pwl = pwl->next) {
        if (strcmp((char *)pwl->user, (char *)param->username) != 0) {
            /* Wrong user. */
            continue;
        }
        switch (pwl->pwtype) {
            case CL:
                if (pwl->password == NULL || pwl->password[0] == '\0') {
                    /* Allow empty passwords. */
                    rc = AUTH_SUCCESSFUL;
                    goto result;
                }
                if (PasswordCheck((const char *)param->password, &param->sincr, (const char *)pwl->password)) {
                    rc = AUTH_SUCCESSFUL;
                    goto result;
                }
                rc = AUTH_WRONG_PASSWORD;
                goto result;
            case CR:
            case NT:
            case LM:
                /* Not supported yet. */
                log_err("only CL password records are supported at the moment, skipping CR/NT/LM");
                continue;
            default:
                rc = 999;
                goto result;
        }
    }
result:
    return rc;
}

static uint8_t hex2val(const char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    log_err("invalid hex char: '%c'\n", c);
    abort();
}

PLUGINAPI int PLUGINCALL RunTest(const struct pluginlink *link, int argc, char **argv) {
    if (argc < 3) {
        log_err_config(link, "format is 'plugin BoundAuth.dll %s <hexstr> <expected> [alphabet]'", argv[0]);
        return RETURN_INVALID_INPUT;
    }

    char *hexstr = argv[1];
    char *expected = argv[2];
    char *alphabet;
    if (argc >= 4) {
        alphabet = argv[3];
    } else {
        alphabet = ALPHABET_BASE32_UPPER;
    }
    size_t hexstr_len = strlen(hexstr);
    if (hexstr_len % 2) {
        log_err_config(link, "hexstr length is odd = %zu chars in length", hexstr_len);
        return RETURN_INVALID_INPUT;
    }
    size_t source_len = hexstr_len >> 1;
    uint8_t *source = alloca(source_len);
    uint8_t *source_ptr = source;
    for (size_t i = 0; i < hexstr_len; i += 2) {
        *source_ptr++ = ((uint8_t)(hex2val(hexstr[i]) << 4) | hex2val(hexstr[i + 1]));
    }
    char actual[256] = "\0";
    StringizeBytes(source, source_len, alphabet, strlen(alphabet), actual, sizeof(actual));
    if (strcasecmp(expected, actual) != 0) {
        log_err_config(link, "expected '%s', actual '%s'", expected, actual);
        return RETURN_PROCESSING_ERROR;
    }
    return RETURN_SUCCESS;
}

PLUGINAPI int PLUGINCALL ConvertPassword(struct pluginlink *link, int argc, char **argv) {
    if (argc < 3) {
        log_err_config(link, "format is 'plugin BoundAuth.dll %s <password> <addr>'", argv[0]);
        return RETURN_INVALID_INPUT;
    }
    const char *pw_private = argv[1];
    const char *addr_string = argv[2];
    sockaddr_used addr = {0};
    uint16_t addr_family;
    if (strchr(addr_string, '.') != NULL && strchr(addr_string, ':') == NULL) {
        addr_family = AF_INET;
    } else if (strchr(addr_string, '.') == NULL && strchr(addr_string, ':') != NULL) {
        addr_family = AF_INET6;
    } else {
        log_err_config(link, "address '%s' is not a valid IPv4 neither IPv6 address", addr_string);
        return RETURN_INVALID_INPUT;
    }
    if (inet_pton(addr_family, addr_string, SAADDR(&addr)) != 1) {
        log_err_config(link, "address '%s' is not a valid IPv4 neither IPv6 address", addr_string);
        return RETURN_INVALID_INPUT;
    }

    char *pw_public = alloca(PluginConfig.len + 1);
    pw_public[PluginConfig.len] = '\0';
    PasswordBoundize(pw_private, &addr, pw_public);
    assert(pw_public[PluginConfig.passwordLen] == '\0');

    log_err_config(link, "public password for { '%s', '%s' }:    %s", pw_private, addr_string, pw_public);
    return RETURN_SUCCESS;
}

PLUGINAPI int PLUGINCALL Initialize(struct pluginlink *link, int argc, char **argv) {
    if (PluginConfig.initialized) {
        log_err_config(link, "plugin already initialized");
        return RETURN_INVALID_INPUT;
    }

    /* DONE: parse passwordLen= and other parameters. */
    for (int i = 1; i < argc; ++i) {
        const char *val = strtok(argv[i], "=");
        if (val && strcmp(argv[i], "len") == 0) {
            if (sscanf(val, "%hhu", &PluginConfig.len) != 1 || PluginConfig.len == 0) {
                log_err_config(link, "%s= should be followed by a positive integer", argv[i]);
                return RETURN_INVALID_INPUT;
            }
        } else if (val && strcmp(argv[i], "secret") == 0) {
            PluginConfig.secret.len = strlen(val);
            if ((PluginConfig.secret.data = malloc(PluginConfig.secret.len + 1)) == NULL) {
                return RETURN_INTERNAL_ERROR;
            }
            strcpy(PluginConfig.secret.data, val);
        } else if (val && strcmp(argv[i], "alphabet") == 0) {
            if (strcmp(val, "base32_lower") == 0) {
                PluginConfig.alphabet = STR_EXPRC(ALPHABET_BASE32_LOWER);
            } else if (strcmp(val, "base32_upper") == 0 || strcmp(val, "base32") == 0) {
                PluginConfig.alphabet = STR_EXPRC(ALPHABET_BASE32_UPPER);
            } else if (strcmp(val, "base64") == 0) {
                PluginConfig.alphabet = STR_EXPRC(ALPHABET_BASE64);
            } else if (strcmp(val, "convenient") == 0) {
                PluginConfig.alphabet = STR_EXPRC(ALPHABET_CONVENIENT);
            } else {
                PluginConfig.alphabet = STR_EXPR(val);
            }
        }
    }

    /* Ensure the alphabet is valid. */
    static_assert(sizeof(char) == sizeof(uint8_t));
    /*static_assert((uint8_t)(255 + 1) == 0);*/
    uint8_t seen[32] = { 0 };
    for (size_t i = 0; i < PluginConfig.alphabet.len; ++i) {
        char c = PluginConfig.alphabet.data[i];
        if (seen[c / 8] & (1 << (c % 8))) {
            log_err_config(link, "alphabet must be unique; contains duplicate char '%c'", c);
            return RETURN_INVALID_INPUT;
        }
        seen[c / 8] |= (1 << (c % 8));
    }

    static struct auth bound_auth = {
        .desc = "bound",
        .authenticate = BoundAuth_AuthenticateFunc,
    };

    for (struct auth *a = link->authfuncs; a != NULL; a = a->next) {
        if (strcmp(a->desc, bound_auth.desc) == 0) {
            log_err_config(link, "auth bound already registered");
            return RETURN_PROCESSING_ERROR;
        }
    }

    bound_auth.authorize = link->checkACL;
    bound_auth.next = link->authfuncs->next;
    link->authfuncs->next = &bound_auth;

    p_link = link;
    return RETURN_SUCCESS;
}

#if !defined(_WIN32)
__attribute__((destructor))
#endif
static void PluginDestructor(void) {
    if (PluginConfig.secret.data != NULL) {
        free(PluginConfig.secret.data);
    }
}

#if defined(_WIN32)
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_DETACH) {
        PluginDestructor();
    }
    return TRUE;
}
#endif
