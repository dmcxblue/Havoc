SHELL := /bin/bash
ifndef VERBOSE
.SILENT:
endif

# main build target. compiles the teamserver and client
all: ts-build client-build

# teamserver building target
ts-build:
	@ echo "[*] building teamserver"
	@ if [ ! -d "data" ]; then mkdir data; fi
	@ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
	@ sudo setcap 'cap_net_bind_service=+ep' havoc # this allows you to run the server as a regular user

dev-ts-compile:
	@ echo "[*] compile teamserver"
	@ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go 

ts-cleanup:
	@ echo "[*] teamserver cleanup"
	@ rm -rf ./teamserver/bin
	@ rm -rf ./data/loot
	@ rm -rf ./data/*-w64-mingw32-cross
	@ rm -rf ./data/*.db
	@ rm -rf ./data/server.*
	@ rm -rf ./teamserver/.idea
	@ rm -rf ./havoc

# client building and cleanup targets 
client-build:
	@ echo "[*] building client"
	@ git submodule update --init --recursive
	@ mkdir -p client/Build; cd client/Build; cmake ..
	@ if [ -d "client/Modules" ]; then echo "Modules installed"; else BRANCH=`git rev-parse --abbrev-ref HEAD`; git clone --recurse-submodules https://github.com/HavocFramework/Modules client/Modules --single-branch --branch "$$BRANCH" || git clone --recurse-submodules https://github.com/HavocFramework/Modules client/Modules --single-branch --branch main; fi
	@ if [ -f "client/Modules/nanodump/nanodump.py" ]; then sed -i 's|C:\\Windows\\notepad.exe|C:\\\\Windows\\\\notepad.exe|g' client/Modules/nanodump/nanodump.py; fi
	@ cmake --build client/Build -- -j 4
	@ $(MAKE) bof-build

client-build-mac:
	@ echo "[*] building client"
	@ git submodule update --init --recursive
	@ mkdir -p client/Build; cd client/Build; cmake ..
	@ if [ -d "client/Modules" ]; then echo "Modules installed"; else BRANCH=`git rev-parse --abbrev-ref HEAD`; git clone --recurse-submodules https://github.com/HavocFramework/Modules client/Modules --single-branch --branch "$$BRANCH" || git clone --recurse-submodules https://github.com/HavocFramework/Modules client/Modules --single-branch --branch main; fi
	@ if [ -f "client/Modules/nanodump/nanodump.py" ]; then sed -i 's|C:\\Windows\\notepad.exe|C:\\\\Windows\\\\notepad.exe|g' client/Modules/nanodump/nanodump.py; fi
	@ rm client/external/toml/toml/exception.hpp ; cp exception_mac.hpp client/external/toml/toml/exception.hpp
	@ cmake --build client/Build -- -j 4
	@ $(MAKE) bof-build

client-cleanup:
	@ echo "[*] client cleanup"
	@ rm -rf ./client/Build
	@ rm -rf ./client/build
	@ rm -rf ./client/Bin/*
	@ rm -rf ./client/Data/database.db
	@ rm -rf ./client/.idea
	@ rm -rf ./client/cmake-build-debug
	@ rm -rf ./client/Havoc


MINGW_CC     = x86_64-w64-mingw32-gcc
MINGW_CC_x86 = i686-w64-mingw32-gcc
MINGW_CCXX   = x86_64-w64-mingw32-g++

# CS-Remote-OPs-BOF extras registered by client/Modules/RemoteOps/RemoteOpsExtra.py
# The vendored source tree is left untouched — we only compile from it into
# client/Modules/RemoteOps/bin/ where the Python loader expects the .o files.
REMOTEOPS_EXTRA_BOFS := \
	chromeKey get_priv office_tokens procdump ProcessDestroy \
	ProcessListHandles sc_config sc_failure schtaskscreate schtasksdelete \
	schtasksrun schtasksstop shspawnas suspendresume unexpireuser

REMOTEOPS_SRC    := client/Modules/RemoteOps/CS-Remote-OPs-BOF/src
REMOTEOPS_COMMON := $(REMOTEOPS_SRC)/common
REMOTEOPS_BIN    := client/Modules/RemoteOps/bin

# custom BOF modules — compiled on every client-build
bof-build:
	@ echo "[*] compiling custom BOF modules"
	@ mkdir -p client/Modules/PrivKit/bin
	@ if [ -f client/Modules/PrivKit/repo/src/PrivKitAll/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/PrivKit/bin/PrivKitAll.x64.o \
			-c client/Modules/PrivKit/repo/src/PrivKitAll/entry.c \
			-DBOF -I client/Modules/PrivKit/repo/src/common -fno-builtin && \
		echo "  -> PrivKit OK"; \
	fi
	@ mkdir -p client/Modules/Icacls/bin
	@ if [ -f client/Modules/Icacls/src/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/Icacls/bin/icacls.x64.o \
			-c client/Modules/Icacls/src/entry.c \
			-DBOF -fno-builtin && \
		echo "  -> Icacls OK"; \
	fi
	@ mkdir -p client/Modules/Clipboard/bin
	@ if [ -f client/Modules/Clipboard/src/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/Clipboard/bin/clipboard.x64.o \
			-c client/Modules/Clipboard/src/entry.c \
			-DBOF && \
		echo "  -> Clipboard OK"; \
	fi
	@ mkdir -p client/Modules/Keylogger/bin
	@ if [ -f client/Modules/Keylogger/src/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/Keylogger/bin/keylogger.x64.o \
			-c client/Modules/Keylogger/src/entry.c \
			-DBOF && \
		echo "  -> Keylogger OK"; \
	fi
	@ mkdir -p client/Modules/LiveDesktop/bin
	@ if [ -f client/Modules/LiveDesktop/src/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/LiveDesktop/bin/livedesktop.x64.o \
			-c client/Modules/LiveDesktop/src/entry.c \
			-DBOF -fno-builtin && \
		echo "  -> LiveDesktop OK"; \
	fi
	@ mkdir -p client/Modules/GhostTask/bin
	@ if [ -f client/Modules/GhostTask/src/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/GhostTask/bin/ghosttask.x64.o \
			-c client/Modules/GhostTask/src/entry.c \
			-DBOF && \
		echo "  -> GhostTask OK"; \
	fi
	@ mkdir -p client/Modules/UacCheck/bin
	@ if [ -f client/Modules/UacCheck/src/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/UacCheck/bin/uaccheck.x64.o \
			-c client/Modules/UacCheck/src/entry.c \
			-I client/Modules/RemoteOps/CS-Remote-OPs-BOF/src/common \
			-DBOF -Os -fno-builtin && \
		echo "  -> UacCheck OK"; \
	fi
	@ mkdir -p client/Modules/Bitsadmin/bin
	@ if [ -f client/Modules/Bitsadmin/src/entry.c ]; then \
		$(MINGW_CC) -o client/Modules/Bitsadmin/bin/bitsadmin.x64.o \
			-c client/Modules/Bitsadmin/src/entry.c \
			-DBOF -Os -fno-builtin && \
		echo "  -> Bitsadmin OK"; \
	fi
	@ mkdir -p client/Modules/WmiSubscriptions/bin
	@ if [ -f client/Modules/WmiSubscriptions/src/wmisubscriptions.cpp ]; then \
		$(MINGW_CCXX) -o client/Modules/WmiSubscriptions/bin/wmisubscriptions.x64.o \
			-c client/Modules/WmiSubscriptions/src/wmisubscriptions.cpp \
			-I client/Modules/WmiSubscriptions/include -Os -w -mno-stack-arg-probe && \
		echo "  -> WmiSubscriptions OK"; \
	fi
	@ if [ -f client/Modules/UacBonanza/repo/Makefile ]; then \
		$(MAKE) --no-print-directory -C client/Modules/UacBonanza/repo bof >/dev/null 2>&1 && \
		echo "  -> UacBonanza (7 UAC bypass BOFs) OK"; \
	fi
	@ mkdir -p $(REMOTEOPS_BIN)
	@ for bof in $(REMOTEOPS_EXTRA_BOFS); do \
		src=$(REMOTEOPS_SRC)/Remote/$$bof/entry.c; \
		if [ -f "$$src" ]; then \
			$(MINGW_CC)     -o $(REMOTEOPS_BIN)/$$bof.x64.o -c "$$src" -I $(REMOTEOPS_COMMON) -DBOF -Os && \
			$(MINGW_CC_x86) -o $(REMOTEOPS_BIN)/$$bof.x86.o -c "$$src" -I $(REMOTEOPS_COMMON) -DBOF -Os && \
			echo "  -> RemoteOps extra: $$bof OK"; \
		else \
			echo "  -> RemoteOps extra: $$bof (source missing, skipped)"; \
		fi; \
	done

# cleanup target
clean: ts-cleanup client-cleanup
	@ rm -rf ./data/*.db
	@ rm -rf payloads/Demon/.idea
