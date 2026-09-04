CC     := x86_64-w64-mingw32-gcc
CFLAGS := -c -Os -DBOF -fno-builtin
SRC    := src/entry.c
OUT    := bin/bitsadmin.x64.o

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)
	@echo "compiled -> $(OUT)"

clean:
	rm -f $(OUT)
