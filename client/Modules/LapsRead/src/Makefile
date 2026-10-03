BOFNAME    := ldapsearch
CS_SA_ROOT := ../../SituationalAwareness/CS-Situational-Awareness-BOF/src
COMINCLUDE := -I $(CS_SA_ROOT)/common
CC_x64     := x86_64-w64-mingw32-gcc
CC_x86     := i686-w64-mingw32-gcc
CFLAGS     := -Os -DBOF

all:
	$(CC_x64) $(COMINCLUDE) $(CFLAGS) -c entry.c -o ../bin/$(BOFNAME).x64.o
	$(CC_x86) $(COMINCLUDE) $(CFLAGS) -c entry.c -o ../bin/$(BOFNAME).x86.o

clean:
	rm -f ../bin/$(BOFNAME).x64.o ../bin/$(BOFNAME).x86.o
