CC     := x86_64-w64-mingw32-g++
LD     := x86_64-w64-mingw32-ld
CFLAGS := -Os -w -mno-stack-arg-probe -fno-exceptions -fno-rtti -fno-builtin
SRCS   := $(wildcard src/*.cpp)
OBJS   := $(patsubst src/%.cpp,build/%.o,$(SRCS))
HDRS   := $(wildcard include/*.h)
OUT    := bin/gpresult.x64.o

.PHONY: all clean

all: $(OUT)

build/%.o: src/%.cpp $(HDRS)
	@mkdir -p build
	$(CC) $(CFLAGS) -I include -c $< -o $@

# partial link keeps relocations + __imp_* undefineds — required BOF shape
$(OUT): $(OBJS)
	@mkdir -p bin
	$(LD) -r -o $(OUT) $(OBJS)
	@echo "compiled -> $(OUT)"

clean:
	rm -rf build $(OUT)
