# Havoc Demon Agent

Havoc Demon Agent source code written in C and assembly  

# Directories

## src/asm
assembly code (return address stack spoofing)

## src/core
core functions ( connect to server, dynamically load win32 apis / syscalls )

## src/crypt
encryption / decryption functions

## src/inject 
injection functions and utilities

## src/main
Entry point of an PE executable 
- MainExe.c

Entry point of a Service executable
- MainSvc.c
    
Entry point of a Dll
- MainDll.c

### NOTE about the `CMakeLists.txt` file
Do not modify it or use it. This is only for developing and editing the Demon source code in CLion or any other IDE that supports CMake. It is only there to provide references and improve workflow, it has no build purpose.