/*
 * test_bof.c — Phase 0 smoke test.
 * Validates: go() entry, arg extraction, Beacon output, build pipeline.
 */
#include "bofdefs.h"

DECLSPEC_EXPORT void go(char* args, int len) {
    datap parser;
    char* name;
    int nlen = 0;

    BeaconDataParse(&parser, args, len);
    name = BeaconDataExtract(&parser, &nlen);

    internal_printf("[test_bof] hello from a BOF\n");
    if (name && nlen > 0) {
        internal_printf("[test_bof] arg = '%.*s' (%d bytes)\n", nlen, name, nlen);
    } else {
        internal_printf("[test_bof] no args passed\n");
    }
}
