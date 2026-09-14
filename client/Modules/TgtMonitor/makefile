MONITOR := tgt-monitor
RENEW   := tgt-renew

CCX64  := x86_64-w64-mingw32-gcc
CCX86  := i686-w64-mingw32-gcc
CFLAGS := -Wall -Werror -Os -I include -D_NO_NTDLL_CRT_

.PHONY: all clean

all: monitor renew

monitor: bin/$(MONITOR).x64.o bin/$(MONITOR).x86.o
renew:   bin/$(RENEW).x64.o   bin/$(RENEW).x86.o

bin/$(MONITOR).x64.o: src/monitor.c include/common.c include/beacon.h include/common.h include/structs.h
	@mkdir -p bin
	$(CCX64) -c src/monitor.c -o $@ $(CFLAGS)

bin/$(MONITOR).x86.o: src/monitor.c include/common.c include/beacon.h include/common.h include/structs.h
	@mkdir -p bin
	$(CCX86) -c src/monitor.c -o $@ $(CFLAGS)

bin/$(RENEW).x64.o: src/renew.c include/common.c include/crypto.c include/asn.c include/beacon.h include/common.h include/structs.h
	@mkdir -p bin
	$(CCX64) -c src/renew.c -o $@ $(CFLAGS)

bin/$(RENEW).x86.o: src/renew.c include/common.c include/crypto.c include/asn.c include/beacon.h include/common.h include/structs.h
	@mkdir -p bin
	$(CCX86) -c src/renew.c -o $@ $(CFLAGS)

clean:
	rm -f bin/*.o
