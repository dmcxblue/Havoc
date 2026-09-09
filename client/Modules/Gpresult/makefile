CC     := x86_64-w64-mingw32-g++
CFLAGS := -c -Os -w -mno-stack-arg-probe
SRC    := src/entry.cpp
OUT    := bin/gpresult.x64.o

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRC)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(SRC) -I include -o $(OUT)
	@echo "compiled -> $(OUT)"

clean:
	rm -f $(OUT)
