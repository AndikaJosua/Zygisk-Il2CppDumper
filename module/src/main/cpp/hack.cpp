//
// Created by Perfare on 2020/7/4.
//
// Modified: Added /proc/self/maps scanner to bypass failing dlopen/NativeBridge hooks
// in emulator translation layer environments.
//

#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <chrono>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>
#include <cerrno>

// ---------------------------------------------------------------------------
// /proc/self/maps scanner — proactive memory-map based detection
// ---------------------------------------------------------------------------

// The maps-based scanner thread entry point.
// Polls /proc/self/maps every 500ms until libil2cpp.so appears, then hands off
// directly to our codebase's existing core dumping function.
static void hack_start_maps(const char *game_data_dir) {
    LOGI("Perfare: Detached background maps scanning thread successfully spun up (tid=%d).", gettid());

    std::string data_dir(game_data_dir);
    unsigned int loop_count = 0;
    uintptr_t base_addr = 0;

    constexpr auto POLL_INTERVAL = std::chrono::milliseconds(500);

    // Continuous loop inside the background thread that opens and reads /proc/self/maps
    while (true) {
        loop_count++;
        LOGI("Perfare: Start of scanning iteration loop (loop_count=%u).", loop_count);

        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) {
            LOGE("Perfare: Exception/Error: Failed to open /proc/self/maps on iteration %u.", loop_count);
            std::this_thread::sleep_for(POLL_INTERVAL);
            continue;
        }

        std::string line;
        bool found_base = false;

        while (std::getline(maps, line)) {
            // Filter map lines specifically looking for the substring "libil2cpp.so"
            if (line.find("libil2cpp.so") == std::string::npos) {
                continue;
            }

            LOGI("Perfare: Substring 'libil2cpp.so' successfully seen in maps line: %s", line.c_str());

            // Once the target string is found, verify that the line contains valid segment permissions (such as 'r-xp' or 'r--p').
            // Parse permissions. Maps line format: "start-end perms offset dev inode pathname"
            size_t address_end = line.find(' ');
            if (address_end == std::string::npos) {
                LOGE("Perfare: Exception/Error: Parsing failure — space separating address range not found in line: %s", line.c_str());
                continue;
            }

            size_t perms_start = address_end;
            while (perms_start < line.length() && line[perms_start] == ' ') {
                perms_start++;
            }

            if (perms_start + 4 > line.length()) {
                LOGE("Perfare: Exception/Error: Parsing failure — permissions field out of bounds in line: %s", line.c_str());
                continue;
            }

            std::string perms = line.substr(perms_start, 4);
            if (perms != "r-xp" && perms != "r--p") {
                LOGI("Perfare: Skipping libil2cpp.so segment with permissions: %s", perms.c_str());
                continue;
            }

            // Extract the start address from the beginning of the matching line,
            // parse it from a hexadecimal string format into a native memory address pointer,
            // and handle any potential parsing exceptions safely.
            size_t dash = line.find('-');
            if (dash == std::string::npos || dash > address_end) {
                LOGE("Perfare: Exception/Error: Parsing failure — dash separating address range not found in line: %s", line.c_str());
                continue;
            }

            std::string start_addr_str = line.substr(0, dash);
            if (start_addr_str.empty()) {
                LOGE("Perfare: Exception/Error: Parsing failure — start address string is empty.");
                continue;
            }

            // Verify characters are valid hex to handle potential parsing anomalies safely
            bool is_valid_hex = true;
            for (char c : start_addr_str) {
                if (!isxdigit(static_cast<unsigned char>(c))) {
                    is_valid_hex = false;
                    break;
                }
            }

            if (!is_valid_hex) {
                LOGE("Perfare: Exception/Error: Parsing failure — invalid hex digit in address string: %s", start_addr_str.c_str());
                continue;
            }

            char *endptr = nullptr;
            errno = 0;
            unsigned long long parsed_val = strtoull(start_addr_str.c_str(), &endptr, 16);
            if (endptr == nullptr || *endptr != '\0' || errno == ERANGE) {
                LOGE("Perfare: Exception/Error: Parsing failure — strtoull failed for address string: %s (errno=%d)", start_addr_str.c_str(), errno);
                continue;
            }

            base_addr = static_cast<uintptr_t>(parsed_val);
            LOGI("Perfare: Memory address parsed successfully. Hex representation: 0x%" PRIxPTR, base_addr);
            found_base = true;
            break;
        }

        // Cleanly close the file streams after every loop iteration to avoid file descriptor exhaustion.
        maps.close();

        if (found_base && base_addr != 0) {
            break;
        }

        // Implement a safe polling delay (e.g., 500ms) within each iteration to prevent high CPU utilization.
        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    // Pass that base address value directly into our codebase's existing core dumping function to kick off the extraction process.
    LOGI("Perfare: Starting core dumping/extraction with base address 0x%" PRIxPTR, base_addr);
    il2cpp_api_init_from_base(base_addr);
    il2cpp_dump(data_dir.c_str());
    LOGI("Perfare: Extraction process completed.");
}

// ---------------------------------------------------------------------------
// JNI / NativeBridge helpers (unchanged)
// ---------------------------------------------------------------------------

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                "currentApplication",
                                                                "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                  "getApplicationInfo",
                                                                  "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version;
    void *initialize;

    void *(*loadLibrary)(const char *libpath, int flag);

    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);

    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;

    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    //TODO 等待houdini初始化
    sleep(5);

    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart,
                                                                             "JNI_GetCreatedJavaVMs");
    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        LOGE("GetCreatedJavaVMs error");
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty()) {
        LOGE("GetLibDir error");
        return false;
    }
    if (lib_dir.find("/lib/x86") != std::string::npos) {
        LOGI("no need NativeBridge");
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        LOGI("native bridge: %s", native_bridge.data());
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }
    if (nb) {
        LOGI("nb %p", nb);
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
            LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
            LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            LOGI("arm path %s", path);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                LOGI("arm handle %p", arm_handle);
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle,
                                                                                  "JNI_OnLoad",
                                                                                  nullptr, 0);
                LOGI("JNI_OnLoad %p", init);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Entry point — dispatches to maps scanner first, then original fallback
// ---------------------------------------------------------------------------

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("Perfare: Initialization entry point (hack_prepare) triggered (tid=%d).", gettid());
    int api_level = android_get_device_api_level();
    LOGI("Perfare: API level detected: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        LOGI("Perfare: Native bridge translation library loaded successfully. Main hook thread exiting.");
        return;
    }
    LOGW("Perfare: NativeBridgeLoad failed or bypassed. Falling back to maps scanner.");
#endif

    // Spawn a detached background native thread to handle the memory scanning process.
    // Ensure the main hook thread exits immediately.
    LOGI("Perfare: Spawning detached background thread for maps scanning in hack_prepare.");
    std::string data_dir(game_data_dir);
    std::thread scan_thread([data_dir]() {
        hack_start_maps(data_dir.c_str());
    });
    scan_thread.detach();
    LOGI("Perfare: Detached scanner thread spawned. Main hook thread exiting.");
}

#if defined(__arm__) || defined(__aarch64__)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    LOGI("Perfare: ARM JNI_OnLoad entry point triggered (tid=%d).", gettid());
    
    // Spawn a detached background native thread to handle the memory scanning process.
    // Ensure the main hook thread exits immediately.
    LOGI("Perfare: Spawning detached background thread for maps scanning in JNI_OnLoad.");
    std::string data_dir(game_data_dir);
    std::thread hack_thread([data_dir]() {
        hack_start_maps(data_dir.c_str());
    });
    hack_thread.detach();
    
    LOGI("Perfare: Detached scanner thread spawned from JNI_OnLoad. Main JNI_OnLoad thread exiting.");
    return JNI_VERSION_1_6;
}

#endif