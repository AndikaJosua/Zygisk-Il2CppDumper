//
// Created by Perfare on 2020/7/4.
//

#ifndef ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H
#define ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H

#include <cstdint>

// Initialize il2cpp API functions using a handle from dlopen/xdl_open
void il2cpp_api_init(void *handle);

// Initialize il2cpp API functions by walking the ELF at the given base address
// obtained from /proc/self/maps. This is the fallback when dlopen fails entirely.
void il2cpp_api_init_from_base(uintptr_t base);

void il2cpp_dump(const char *outDir);

#endif //ZYGISK_IL2CPPDUMPER_IL2CPP_DUMP_H
