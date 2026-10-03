CC_x64 := x86_64-w64-mingw32-g++
CC_x86 := i686-w64-mingw32-g++

CFLAGS := -c -Os -s -w -I . \
          -fno-sized-deallocation -fno-exceptions -fno-rtti \
          -fno-asynchronous-unwind-tables -fno-stack-protector \
          -mno-stack-arg-probe \
          -fno-use-cxa-atexit -ffunction-sections -fdata-sections

SRCDIR := ../source
BIN    := ../bin

all: $(BIN)/kerb_ptt.x64.o $(BIN)/kerb_ptt.x86.o $(BIN)/kerb_purge.x64.o $(BIN)/kerb_purge.x86.o $(BIN)/overpass.x64.o $(BIN)/overpass.x86.o

$(BIN)/overpass.x64.o: $(SRCDIR)/overpass.c
	@mkdir -p $(BIN)
	$(CC_x64) $(CFLAGS) -o $@ $<

$(BIN)/overpass.x86.o: $(SRCDIR)/overpass.c
	@mkdir -p $(BIN)
	$(CC_x86) $(CFLAGS) -o $@ $<

$(BIN)/kerb_ptt.x64.o: $(SRCDIR)/kerb_ptt.c
	@mkdir -p $(BIN)
	$(CC_x64) $(CFLAGS) -o $@ $<

$(BIN)/kerb_ptt.x86.o: $(SRCDIR)/kerb_ptt.c
	@mkdir -p $(BIN)
	$(CC_x86) $(CFLAGS) -o $@ $<

$(BIN)/kerb_purge.x64.o: $(SRCDIR)/kerb_purge.c
	@mkdir -p $(BIN)
	$(CC_x64) $(CFLAGS) -o $@ $<

$(BIN)/kerb_purge.x86.o: $(SRCDIR)/kerb_purge.c
	@mkdir -p $(BIN)
	$(CC_x86) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN)/kerb_ptt.*.o $(BIN)/kerb_purge.*.o $(BIN)/overpass.*.o
