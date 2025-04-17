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

#define AUTH_SUCCESSFUL 0
#define AUTH_DENIED 1
#define AUTH_NO_MATCHING_RULE 3
#define AUTH_NO_USERNAME_PRESENT 4
#define AUTH_NO_USERNAME_FOUND 5
#define AUTH_WRONG_PASSWORD 6

#include "../../structures.h"
#include <stdbool.h>
#include <malloc.h>

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

#define sha256_init() picohash_init_sha256(&ctx)
#define sha256_update(data, len) picohash_update(&ctx, data, len)
#define sha256_final(out) picohash_final(&ctx, out)

#define HMAC_SHA256_PAD_LEN 64
#define HMAC_LEN PICOHASH_SHA256_DIGEST_LENGTH

/* Сложно сделать идеальный однозначный алфавит. Фак. */
#define ALPHABET_DEFAULT "23456789ACDEFGHJKMNPQRTUVWXY-_=+"
#define ALPHABET_DEFAULT_SIZE (sizeof(ALPHABET_DEFAULT) - 1)
static_assert(ALPHABET_DEFAULT_SIZE == 32);

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

static void hmac_sha256(const uint8_t *key, const size_t key_len,
                        const uint8_t *msg, const size_t msg_len,
                        uint8_t *out_digest) {

    picohash_ctx_t ctx;
    uint8_t key_block[HMAC_SHA256_PAD_LEN];
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

/* Need to read bits in the order same an binary string instead. */
static void StringizeBytes(const uint8_t *data, const size_t len, const char *alphabet, const size_t alphabet_len, char *str, const size_t str_len) {
    size_t currByte = 0;
    size_t currByteBit = 0;
    uint8_t bitsPerChar = 0;
    for (size_t al = alphabet_len - 1; al; al >>= 1) { ++bitsPerChar; }
    for (size_t pos = 0; pos < str_len; ++pos) {
        uint8_t val = (data[currByte] >> currByteBit) & ((1U << bitsPerChar) - 1);
        currByteBit += bitsPerChar;
        if (currByteBit >= 8) {
            ++currByte;
            currByteBit -= 8;
            val = val << currByteBit | (data[currByte] & ((1U << currByteBit) - 1));
        }
        *str++ = alphabet[val];
    }
}

static bool PasswordCheck(const uint8_t *username, const uint8_t *pw_public,
#ifdef NOIPV6
struct sockaddr_in
#else
struct sockaddr_in6
#endif
                         *addr, const uint8_t *pw_private) {
    if (strlen((const char *)pw_public) != PluginConfig.passwordLen) {
        return false;
    }
    uint8_t hmac[HMAC_LEN];
    hmac_sha256(pw_private, strlen((const char *)pw_private), SAADDR(addr), SAADDRLEN(addr), hmac);
    char *token = alloca(PluginConfig.passwordLen + 1);
    token[PluginConfig.passwordLen] = '\0';
    StringizeBytes(hmac, countof(hmac), PluginConfig.alphabet, PluginConfig.alphabetLen, token, PluginConfig.passwordLen);
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
    /* TODO: add lock over conf->pwl!! */
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
                if (PasswordCheck(param->username, param->password, &param->sincr, pwl->password)) {
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

PLUGINAPI int PLUGINCALL Initialize(struct pluginlink *link, int argc, char **argv) {
    p_link = link;

    static struct auth bound_auth = {
        .desc = "bound",
        .authenticate = BoundAuth_AuthenticateFunc,
        .authorize = NULL,
    };
    bound_auth.next = link->authfuncs->next;
    link->authfuncs->next = &bound_auth;

    return 0;
}

static void PluginConstructor(void) { }

static void PluginDestructor(void) { }

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
