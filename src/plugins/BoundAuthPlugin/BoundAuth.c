/*
   (c) 2025 Alexey Suslov <alexey.s@ultibot.ru>
   All rights are horse-fucked.
*/

#ifdef __cplusplus
#error "Please, compile as C code only"
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

#define ALPHABET_BASE32 "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
/* Сложно сделать идеальный однозначный алфавит. Фак. */
#define ALPHABET_DEFAULT "23456789acdefgjkmnpqsrtuvxyz-_=+"
#define ALPHABET_DEFAULT_SIZE (sizeof(ALPHABET_DEFAULT) - 1)
static_assert(ALPHABET_DEFAULT_SIZE == 32);

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

/* Save the pointer in global area for the easier reuse. */
static struct pluginlink *p_link;

static struct {
    char *alphabet;
    size_t alphabetLen;
    uint8_t passwordLen;
} PluginConfig = {
    .alphabet = ALPHABET_DEFAULT,
    .alphabetLen = ALPHABET_DEFAULT_SIZE,
    .passwordLen = 8,
};

#define HMAC_LEN PICOHASH_SHA256_DIGEST_LENGTH
#undef CUSTOM_HMAC

#if defined(CUSTOM_HMAC)

#define HMAC_SHA256_PAD_LEN 64

#define sha256_init() picohash_init_sha256(&ctx)
#define sha256_update(data, len) picohash_update(&ctx, data, len)
#define sha256_final(out) picohash_final(&ctx, out)

static void hmac_sha256(const uint8_t *key, const size_t key_len,
                        const uint8_t *msg, const size_t msg_len,
                        uint8_t *out_digest) {

    picohash_ctx_t ctx;
    uint8_t key_block[HMAC_SHA256_PAD_LEN] = {0};
    uint8_t ipad[HMAC_SHA256_PAD_LEN];
    uint8_t opad[HMAC_SHA256_PAD_LEN];
    uint8_t inner_hash[PICOHASH_SHA256_DIGEST_LENGTH];

    /* Step 1: Normalize key. */
    if (key_len > countof(key_block)) {
        sha256_init();
        sha256_update(key, key_len);
        sha256_final(key_block);
        memset(&key_block[PICOHASH_SHA256_DIGEST_LENGTH], 0x00, HMAC_SHA256_PAD_LEN - PICOHASH_SHA256_DIGEST_LENGTH);
        _Static_assert(PICOHASH_SHA256_DIGEST_LENGTH <= HMAC_SHA256_PAD_LEN, "wrong lengths");
    } else {
        memcpy(key_block, key, key_len);
    }

    /* Step 2: Prepare pads. */
    for (uint_fast8_t i = 0; i < countof(ipad); i++) {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    /* Step 3: Inner hash. */
    sha256_init();
    sha256_update(ipad, countof(ipad));
    sha256_update(msg, msg_len);
    sha256_final(inner_hash);

    /* Step 4: Outer hash. */
    sha256_init();
    sha256_update(opad, 64);
    sha256_update(inner_hash, 32);
    sha256_final(out_digest);
}
#else
static void hmac_sha256(const uint8_t *key, const size_t key_len,
                        const uint8_t *msg, const size_t msg_len,
                        uint8_t *out_digest) {
    picohash_ctx_t ctx;
    picohash_init_hmac(&ctx, picohash_init_sha256, key, key_len);
    picohash_update(&ctx, msg, msg_len);
    picohash_final(&ctx, out_digest);
}
#endif

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

static void PasswordBoundize(const char *pw_private, sockaddr_used *addr, char *pw_public) {
    uint8_t hmac[HMAC_LEN];
    hmac_sha256((const uint8_t *)pw_private, strlen(pw_private), SAADDR(addr), SAADDRLEN(addr), hmac);
    StringizeBytes(hmac, countof(hmac), PluginConfig.alphabet, PluginConfig.alphabetLen, pw_public, PluginConfig.passwordLen);
}

static bool PasswordCheck(const char *pw_public, sockaddr_used *addr, const char *pw_private) {
    if (strlen(pw_public) != PluginConfig.passwordLen) {
        return false;
    }
#if defined(PLUGIN_DEBUG)
    char *token = alloca(PluginConfig.passwordLen + 1);
    token[PluginConfig.passwordLen] = '\0';
#else
    char *token = alloca(PluginConfig.passwordLen);
#endif
    PasswordBoundize(pw_private, addr, token);
    if (memcmp(token, pw_public, PluginConfig.passwordLen) != 0) {
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
    fprintf(stderr, "invalid hex char: '%c'\n", c);
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
        alphabet = ALPHABET_BASE32;
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

    char *pw_public = alloca(PluginConfig.passwordLen + 1);
    pw_public[PluginConfig.passwordLen] = '\0';
    PasswordBoundize(pw_private, &addr, pw_public);
    assert(pw_public[PluginConfig.passwordLen] == '\0');

    log_err_config(link, "public password for { '%s', '%s' }:    %s", pw_private, addr_string, pw_public);
    return RETURN_SUCCESS;
}

PLUGINAPI int PLUGINCALL Initialize(struct pluginlink *link, int argc, char **argv) {
    p_link = link;

    /* TODO: parse passwordLen= and other parameters. */

    static struct auth bound_auth = {
        .desc = "bound",
        .authenticate = BoundAuth_AuthenticateFunc,
    };
    bound_auth.authorize = link->checkACL;
    bound_auth.next = link->authfuncs->next;
    link->authfuncs->next = &bound_auth;

    return RETURN_SUCCESS;
}
