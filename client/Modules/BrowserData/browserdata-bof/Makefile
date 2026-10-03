# browserdata-bof - HackBrowserData ported to C (BOF + standalone)
#
# Targets:
#   make bof      -> dist/browserdata.x64.o (relocatable COFF, load as BOF)
#   make bofx86   -> dist/browserdata.x86.o
#   make exe      -> dist/hbd.exe (standalone x64)
#   make exex86   -> dist/hbd_x86.exe
#   make all      -> everything above
#   make clean

X64    = x86_64-w64-mingw32-gcc
X86    = i686-w64-mingw32-gcc
X64LD  = x86_64-w64-mingw32-ld
X86LD  = i686-w64-mingw32-ld

ENGINE = core/bd_util.c core/bd_crypto.c core/bd_asn1.c core/bd_json.c \
         core/bd_sqlite.c core/bd_fs.c core/bd_locked.c core/bd_browsers.c \
         core/bd_chromium.c core/bd_firefox.c core/bd_inject.c core/bd_run.c

SQLDEF = -DSQLITE_THREADSAFE=0 \
         -DSQLITE_OMIT_LOAD_EXTENSION \
         -DSQLITE_OMIT_DEPRECATED \
         -DSQLITE_OMIT_PROGRESS_CALLBACK \
         -DSQLITE_OMIT_DATETIME_FUNCS \
         -DSQLITE_OMIT_SHARED_CACHE \
         -DSQLITE_DEFAULT_MEMSTATUS=0 \
         -DSQLITE_LIKE_DOESNT_MATCH_BLOBS \
         -DSQLITE_MAX_EXPR_DEPTH=0 \
         -DNDEBUG

CFLAGS = -O2 -std=gnu99 -DNDEBUG \
         -fno-exceptions -fno-rtti -fno-stack-protector \
         -fno-asynchronous-unwind-tables \
         -fno-builtin \
         -MMD -MP \
         -Icore -Ivendor -Icommon \
         -Wno-unused-parameter -Wno-format -Wno-char-subscripts \
         $(SQLDEF)

# BOF-only: drop the __chkstk_ms stack probe (COFF loader can't resolve it).
# The standalone exe links msvcrt, which supplies __chkstk_ms, so keep it there.
BOF_CFLAGS = $(CFLAGS) -mno-stack-arg-probe

# BOF: engine + shim + entry get the DFR header. sqlite3 and k32_shim do NOT
# (sqlite3 references kernel32 by ADDRESS -> bare externs; k32_shim defines
# those bare names as internal wrappers that resolve via GetProcAddress).
BOF_OBJ_X64 = $(patsubst %.c,build/x64/bof/%.o,$(ENGINE)) \
              build/x64/bof/vendor/sqlite3.o \
              build/x64/bof/common/crt_shim.o build/x64/bof/common/k32_shim.o \
              build/x64/bof/bof/entry.o
BOF_OBJ_X86 = $(patsubst %.c,build/x86/bof/%.o,$(ENGINE)) \
              build/x86/bof/vendor/sqlite3.o \
              build/x86/bof/common/crt_shim.o build/x86/bof/common/k32_shim.o \
              build/x86/bof/bof/entry.o

# EXE: engine + sqlite3 + standalone entry, no DFR (normal import table).
EXE_OBJ_X64 = $(patsubst %.c,build/x64/exe/%.o,$(ENGINE)) \
              build/x64/exe/vendor/sqlite3.o \
              build/x64/exe/standalone/entry.o
EXE_OBJ_X86 = $(patsubst %.c,build/x86/exe/%.o,$(ENGINE)) \
              build/x86/exe/vendor/sqlite3.o \
              build/x86/exe/standalone/entry.o

all: bof bofx86 exe exex86

bof: dist/browserdata.x64.o
bofx86: dist/browserdata.x86.o
exe: dist/hbd.exe
exex86: dist/hbd_x86.exe

dist/browserdata.x64.o: $(BOF_OBJ_X64)
	@mkdir -p dist
	$(X64LD) -r -o $@ $(BOF_OBJ_X64)

dist/browserdata.x86.o: $(BOF_OBJ_X86)
	@mkdir -p dist
	$(X86LD) -r -o $@ $(BOF_OBJ_X86)

dist/hbd.exe: $(EXE_OBJ_X64)
	@mkdir -p dist
	$(X64) $(CFLAGS) -o $@ $(EXE_OBJ_X64) -s -Wl,--subsystem,console

dist/hbd_x86.exe: $(EXE_OBJ_X86)
	@mkdir -p dist
	$(X86) $(CFLAGS) -o $@ $(EXE_OBJ_X86) -s -Wl,--subsystem,console

# ---- BOF engine (with DFR) ----
build/x64/bof/%.o: %.c
	@mkdir -p $(dir $@)
	$(X64) $(BOF_CFLAGS) -include common/bof_dfr.h -c -o $@ $<
build/x86/bof/%.o: %.c
	@mkdir -p $(dir $@)
	$(X86) $(BOF_CFLAGS) -include common/bof_dfr.h -c -o $@ $<

# ---- sqlite3 for BOF (no DFR; bare kernel32 refs are defined by k32_shim) ----
build/x64/bof/vendor/sqlite3.o: vendor/sqlite3.c
	@mkdir -p $(dir $@)
	$(X64) $(BOF_CFLAGS) -c -o $@ $<
build/x86/bof/vendor/sqlite3.o: vendor/sqlite3.c
	@mkdir -p $(dir $@)
	$(X86) $(BOF_CFLAGS) -c -o $@ $<

# ---- k32_shim for BOF (no DFR; defines bare kernel32 names) ----
build/x64/bof/common/k32_shim.o: common/k32_shim.c
	@mkdir -p $(dir $@)
	$(X64) $(BOF_CFLAGS) -c -o $@ $<
build/x86/bof/common/k32_shim.o: common/k32_shim.c
	@mkdir -p $(dir $@)
	$(X86) $(BOF_CFLAGS) -c -o $@ $<

# ---- EXE (no DFR) ----
build/x64/exe/%.o: %.c
	@mkdir -p $(dir $@)
	$(X64) $(CFLAGS) -c -o $@ $<
build/x86/exe/%.o: %.c
	@mkdir -p $(dir $@)
	$(X86) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf build dist

# header dependency tracking: each compile emits a .d next to its .o; include
# them so edits to beacon.h/bd.h/bof_dfr.h trigger correct rebuilds.
-include $(wildcard build/*/*/*/*.d)
