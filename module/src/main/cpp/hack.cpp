//
// Created by Perfare on 2020/7/4.
//
// Completely automated, non-blocking memory map scanner for Unity 6
//

#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <jni.h>
#include <thread>
#include <chrono>
#include <string>
#include <fstream>
#include <cctype>
#include <cerrno>

static void hack_start_maps() {
    LOGI("Perfare: Asynchronous background maps scanning thread active (tid=%d).", gettid());

    // Explicit path setup to guarantee absolute destination stability
    const char *game_data_dir = "/data/data/com.kukouri.wizworld/files";
    unsigned int loop_count = 0;
    uintptr_t base_addr = 0;

    constexpr auto POLL_INTERVAL = std::chrono::milliseconds(500);

    while (true) {
        loop_count++;
        LOGI("Perfare: Map tracking execution pass running (loop_count=%u)...", loop_count);

        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) {
            LOGE("Perfare: Failed to parse execution maps layout on loop %u.", loop_count);
            std::this_thread::sleep_for(POLL_INTERVAL);
            continue;
        }

        std::string line;
        bool found_base = false;

        while (std::getline(maps, line)) {
            if (line.find("libil2cpp.so") == std::string::npos) {
                continue;
            }

            // Target reading executable layout memory regions
            if (line.find("r-xp") == std::string::npos && line.find("r--p") == std::string::npos) {
                continue;
            }

            size_t dash = line.find('-');
            if (dash == std::string::npos) continue;

            std::string start_addr_str = line.substr(0, dash);
            if (start_addr_str.empty()) continue;

            // Simple hex check
            bool is_valid_hex = true;
            for (char c : start_addr_str) {
                if (!isxdigit(static_cast<unsigned char>(c))) {
                    is_valid_hex = false;
                    break;
                }
            }
            if (!is_valid_hex) continue;

            char *endptr = nullptr;
            errno = 0;
            unsigned long long parsed_val = strtoull(start_addr_str.c_str(), &endptr, 16);
            if (endptr == nullptr || *endptr != '\0' || errno == ERANGE) {
                continue;
            }

            base_addr = static_cast<uintptr_t>(parsed_val);
            LOGI("Perfare: Target library segment intercepted successfully: 0x%llx", (unsigned long long)base_addr);
            found_base = true;
            break;
        }

        maps.close();

        if (found_base && base_addr != 0) {
            break;
        }

        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    // Fixed 5-second settling block allowing Unity 6 translation engine tables to fully form
    LOGI("Perfare: Holding dumper thread for 5000ms to achieve internal symbol initialization stability...");
    std::this_thread::sleep_for(std::chrono::milliseconds(5000));

    LOGI("Perfare: Stability window complete. Kicking off dumper engine hooks at address: 0x%llx", (unsigned long long)base_addr);
    il2cpp_api_init_from_base(base_addr);
    
    LOGI("Perfare: Running core extraction pipelines down to local directory files structures...");
    il2cpp_dump(game_data_dir);
    
    LOGI("Perfare: SUCCESS! Memory map dump cycle finished cleanly.");
}

// ---------------------------------------------------------------------------
// Main System Entry Point Dispatches
// ---------------------------------------------------------------------------

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("Perfare: Main entry sequence dispatch triggered.");
    std::thread(hack_start_maps).detach();
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("Perfare: Sub-runtime translation environment context triggered.");
    std::thread(hack_start_maps).detach();
    return JNI_VERSION_1_6;
}
