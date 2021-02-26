#pragma once
#include <stdint.h>

#define MAKE_THUNK(lib, name, hash) extern "C" { int fexthunks_##lib##_##name(void *args); } asm("fexthunks_" #lib "_" #name ":\n.byte 0xF, 0x3F\n.byte " hash );

struct LoadlibArgs {
    const char *Name;
    uintptr_t CallbackThunks;
};

#define LOAD_LIB(name) MAKE_THUNK(fex, loadlib, "0x27, 0x7e, 0xb7, 0x69, 0x5b, 0xe9, 0xab, 0x12, 0x6e, 0xf7, 0x85, 0x9d, 0x4b, 0xc9, 0xa2, 0x44, 0x46, 0xcf, 0xbd, 0xb5, 0x87, 0x43, 0xef, 0x28, 0xa2, 0x65, 0xba, 0xfc, 0x89, 0x0f, 0x77, 0x80") __attribute__((constructor)) static void loadlib() { LoadlibArgs args =  { #name, 0 }; fexthunks_fex_loadlib(&args); }
#define LOAD_LIB_WITH_CALLBACKS(name) MAKE_THUNK(fex, loadlib, "0x27, 0x7e, 0xb7, 0x69, 0x5b, 0xe9, 0xab, 0x12, 0x6e, 0xf7, 0x85, 0x9d, 0x4b, 0xc9, 0xa2, 0x44, 0x46, 0xcf, 0xbd, 0xb5, 0x87, 0x43, 0xef, 0x28, 0xa2, 0x65, 0xba, 0xfc, 0x89, 0x0f, 0x77, 0x80") __attribute__((constructor)) static void loadlib() { LoadlibArgs args =  { #name, (uintptr_t)&callback_unpacks }; fexthunks_fex_loadlib(&args); }