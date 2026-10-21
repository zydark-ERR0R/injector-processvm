#ifndef SHELLCODE_H
#define SHELLCODE_H

#include <cstdint>
#include <cstring>
#include <sys/mman.h>

struct ShellcodeContext {
    uintptr_t dlopen_addr;
    uintptr_t dlerror_addr;
    uintptr_t restore_addr;
    uintptr_t lib_path_addr;
    uintptr_t result_addr;
};

static const uint8_t ARM64_SHELLCODE[] = {
    0xFD, 0x7B, 0xBF, 0xA9,
    0xFD, 0x03, 0x00, 0x91,
    0xE0, 0x03, 0x00, 0xAA,
    0xE1, 0x03, 0x01, 0xAA,
    0xE2, 0x03, 0x02, 0xAA,
    0xE3, 0x03, 0x03, 0xAA,
    0xE4, 0x03, 0x04, 0xAA,
    0x00, 0x00, 0x00, 0x94,
    0xFD, 0x7B, 0xC1, 0xA8,
    0xC0, 0x03, 0x5F, 0xD6
};

struct ShellcodeTemplate {
    static constexpr size_t code_size = sizeof(ARM64_SHELLCODE);
    static constexpr size_t context_size = sizeof(ShellcodeContext);
    static constexpr size_t total_size = code_size + context_size + 256;
};

inline void build_shellcode(uint8_t* buffer, const ShellcodeContext& ctx) {
    memcpy(buffer, ARM64_SHELLCODE, ShellcodeTemplate::code_size);
    memcpy(buffer + ShellcodeTemplate::code_size, &ctx, sizeof(ctx));
}

#endif