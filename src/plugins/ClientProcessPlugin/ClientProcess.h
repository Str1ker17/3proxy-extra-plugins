/*
   (c) 2024 Alexey Suslov <alexey.s@ultibot.ru>
   All rights are horse-fucked.
*/

#pragma once

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

#if 0
static_assert(
    (1 == *(const uint8_t *)&(const ushort){1}),
    "Only little-endian systems are supported. Please add support!"
);
#endif

#define countof(a) (sizeof(a) / sizeof((a)[0]))
#define htobe16(x) ((((x) & 0xffU) << 8) | ((x) >> 8))
#define be16toh htobe16

#define dolog(fmt, ...) fprintf(stderr, "ClientProcess: " fmt "\n", ##__VA_ARGS__)

typedef struct {
    SOCKET s;
    PID pid;
    char *pname;
    char *pname_short;
} ClientProcessSocketInfo;

typedef struct {
    unsigned char hash[16];
    char *path;
    bool isShort: 1;
} ClientProcessACE;
