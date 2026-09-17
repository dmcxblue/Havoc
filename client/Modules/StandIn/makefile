BOFNAME := standin
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP := strip
OPTIONS := -Os -Wall -Wextra -DBOF -I include -fno-builtin -mno-stack-arg-probe

.PHONY: all clean

all: bof_64 bof_86

bof_64:
	mkdir -p bin
	$(CC_x64) -c src/entry.c -o bin/$(BOFNAME).x64.o $(OPTIONS)
	$(STRIP) --strip-unneeded bin/$(BOFNAME).x64.o

bof_86:
	mkdir -p bin
	$(CC_x86) -c src/entry.c -o bin/$(BOFNAME).x86.o $(OPTIONS)
	$(STRIP) --strip-unneeded bin/$(BOFNAME).x86.o

clean:
	rm -f bin/*.o
