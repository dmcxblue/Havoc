#!/bin/bash

# Install required dependencies
sudo apt -qq --yes install golang-go nasm mingw-w64 wget >/dev/null 2>&1

if [ ! -d "data" ]; then
	mkdir data
fi

# Check if system mingw-w64 compilers are available (preferred - more up-to-date)
SYSTEM_MINGW64=$(which x86_64-w64-mingw32-gcc 2>/dev/null)
SYSTEM_MINGW32=$(which i686-w64-mingw32-gcc 2>/dev/null)

if [ -n "$SYSTEM_MINGW64" ] && [ -n "$SYSTEM_MINGW32" ]; then
	echo "[+] Using system mingw-w64 compilers:"
	echo "    x64: $SYSTEM_MINGW64"
	echo "    x86: $SYSTEM_MINGW32"
	$SYSTEM_MINGW64 --version | head -1
else
	echo "[*] System mingw-w64 not found, downloading musl.cc cross compilers..."

	# Download x64 cross compiler if not present
	if [ ! -d "data/x86_64-w64-mingw32-cross" ]; then
		if [ ! -f /tmp/mingw-musl-64.tgz ]; then
			wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-64.tgz
		fi
		tar zxf /tmp/mingw-musl-64.tgz -C data
	fi

	# Download x86 cross compiler if not present
	if [ ! -d "data/i686-w64-mingw32-cross" ]; then
		if [ ! -f /tmp/mingw-musl-32.tgz ]; then
			wget https://musl.cc/i686-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-32.tgz
		fi
		tar zxf /tmp/mingw-musl-32.tgz -C data
	fi

	echo "[+] Using musl.cc cross compilers from data/"
fi
