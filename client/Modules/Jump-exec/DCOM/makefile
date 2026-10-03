BOFNAME := dcom
CC_x64  := x86_64-w64-mingw32-g++
CC_x86  := i686-w64-mingw32-g++

CFLAGS := -c -Os -s -w -I include \
          -fno-sized-deallocation -fno-exceptions -fno-rtti \
          -fno-asynchronous-unwind-tables -fno-stack-protector \
          -fno-use-cxa-atexit -ffunction-sections -fdata-sections

SRC := source/BOF-DCOM.cpp

all: bin/$(BOFNAME).x64.o bin/$(BOFNAME).x86.o

bin/$(BOFNAME).x64.o: $(SRC)
	@mkdir -p bin
	$(CC_x64) $(CFLAGS) -o $@ $<

bin/$(BOFNAME).x86.o: $(SRC)
	@mkdir -p bin
	$(CC_x86) $(CFLAGS) -o $@ $<

clean:
	rm -f bin/$(BOFNAME).x64.o bin/$(BOFNAME).x86.o
