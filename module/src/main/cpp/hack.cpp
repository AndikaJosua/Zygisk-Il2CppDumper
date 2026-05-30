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
#include <cinttypes>  // ADD THIS LINE - provides PRIxPTR macro
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

// ---------------------------------------------------------------------------
// /proc/self/maps scanner — proactive memory-map based detection
// ---------------------------------------------------------------------------

struct MapsEntry {
    uintptr_t start;
    uintptr_t end;
    char perms[5];   // e.g. "r-xp"
    std::string pathname;
};

// Parse a single line from /proc/self/maps into a MapsEntry.
// Format: "start-end perms offset dev inode pathname"
static bool parse_maps_line(const std::string &line, MapsEntry &entry) {
    if (line.empty()) return false;

    // Parse address range: "7f1234000-7f1235000"
    size_t dash = line.find('-');
    if (dash == std::string::npos) return false;

    size_t space1 = line.find(' ', dash);
    if (space1 == std::string::npos) return false;

    // Parse start address
    std::string start_str = line.substr(0, dash);
    // Parse end address
    std::string end_str = line.substr(dash + 1, space1 - dash - 1);

    char *endptr = nullptr;
    entry.start = strtoull(start_str.c_str(), &endptr, 16);
    if (endptr == start_str.c_str()) return false;

    entry.end = strtoull(end_str.c_str(), &endptr, 16);
    if (endptr == end_str.c_str()) return false;

    // Parse permissions (4 chars like "r-xp")
    if (space1 + 1 + 4 > line.size()) return false;
    memcpy(entry.perms, line.c_str() + space1 + 1, 4);
    entry.perms[4] = '\0';

    // Find pathname — it's the last field after the inode.
    // Skip: perms, offset, dev, inode (4 space-separated fields after the address)
    size_t pos = space1 + 1; // start of perms
    int fields_to_skip = 4;  // perms, offset, dev, inode
    for (int i = 0; i < fields_to_skip; ++i) {
        pos = line.find(' ', pos);
        if (pos == std::string::npos) {
            entry.pathname.clear();
            return true; // valid line, just no pathname
        }
        pos++; // skip the space
    }

    // Skip any leading whitespace before the pathname
    while (pos < line.size() && line[pos] == ' ') pos++;

    if (pos < line.size()) {
        entry.pathname = line.substr(pos);
    } else {
        entry.pathname.clear();
    }

    return true;
}

// Scan /proc/self/maps for the first executable mapping of libil2cpp.so.
// Returns the base address (start of the first r-xp or r--p segment) and
// fills out_path with the full filesystem path.
static uintptr_t find_libil2cpp_in_maps(std::string &out_path) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        LOGE("maps_scanner: failed to open /proc/self/maps");
        return 0;
    }

    std::string line;
    uintptr_t base_addr = 0;

    while (std::getline(maps, line)) {
        // Quick substring check before full parse
        if (line.find("libil2cpp.so") == std::string::npos) {
            continue;
        }

        MapsEntry entry;
        if (!parse_maps_line(line, entry)) {
            continue;
        }

        // Verify the pathname actually ends with libil2cpp.so
        // (avoid false matches like "libil2cpp.so.bak" or "notlibil2cpp.so")
        const std::string target = "libil2cpp.so";
        if (entry.pathname.length() < target.length()) {
            continue;
        }
        auto suffix = entry.pathname.substr(entry.pathname.length() - target.length());
        if (suffix != target) {
            continue;
        }

        // We want the first segment — it represents the ELF base.
        // Prefer r-xp (executable code), but accept r--p as the ELF header mapping.
        // The very first mapping of the library in maps is the base address.
        if (base_addr == 0) {
            base_addr = entry.start;
            out_path = entry.pathname;
            LOGI("maps_scanner: found libil2cpp.so at 0x%" PRIxPTR " perms=%s path=%s",
                 entry.start, entry.perms, entry.pathname.c_str());
            // Don't break yet — log all segments for debugging, but use the first base
        }

        LOGD("maps_scanner:   segment 0x%" PRIxPTR "-0x%" PRIxPTR " %s %s",
             entry.start, entry.end, entry.perms, entry.pathname.c_str());
    }

    maps.close();
    return base_addr;
}

// The maps-based scanner thread entry point.
// Polls /proc/self/maps every 500ms until libil2cpp.so appears, then hands off
// to the existing dumper pipeline.
static void hack_start_maps(const char *game_data_dir) {
    LOGI("maps_scanner: thread started (tid=%d), polling for libil2cpp.so...", gettid());

    constexpr int MAX_ATTEMPTS = 120;  // 120 * 500ms = 60 seconds max wait
    constexpr auto POLL_INTERVAL = std::chrono::milliseconds(500);

    uintptr_t base_addr = 0;
    std::string lib_path;

    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
        base_addr = find_libil2cpp_in_maps(lib_path);

        if (base_addr != 0) {
            LOGI("maps_scanner: libil2cpp.so detected on attempt %d", attempt);
            LOGI("maps_scanner: base address = 0x%" PRIxPTR, base_addr);
            LOGI("maps_scanner: full path    = %s", lib_path.c_str());
            break;
        }

        if (attempt % 10 == 0) {
            LOGI("maps_scanner: still waiting for libil2cpp.so (attempt %d/%d)...",
                 attempt, MAX_ATTEMPTS);
        }

        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    if (base_addr == 0) {
        LOGE("maps_scanner: libil2cpp.so not found after %d attempts, giving up.", MAX_ATTEMPTS);
        return;
    }

    // -----------------------------------------------------------------------
    // Strategy: Try to get a proper dl handle using the full path from maps.
    // This often works even when bare-name dlopen("libil2cpp.so") fails,
    // because the full path bypasses the linker's namespace resolution.
    // -----------------------------------------------------------------------
    void *handle = nullptr;

    // Attempt 1: xdl_open with bare name (original approach, may work now that lib is loaded)
    handle = xdl_open("libil2cpp.so", 0);
    if (handle) {
        LOGI("maps_scanner: xdl_open(\"libil2cpp.so\") succeeded: %p", handle);
    }

    // Attempt 2: dlopen with full path from maps
    if (!handle && !lib_path.empty()) {
        handle = dlopen(lib_path.c_str(), RTLD_NOW | RTLD_NOLOAD);
        if (handle) {
            LOGI("maps_scanner: dlopen(\"%s\", RTLD_NOLOAD) succeeded: %p",
                 lib_path.c_str(), handle);
        }
    }

    // Attempt 3: xdl_open with full path
    if (!handle && !lib_path.empty()) {
        handle = xdl_open(lib_path.c_str(), 0);
        if (handle) {
            LOGI("maps_scanner: xdl_open(\"%s\") succeeded: %p",
                 lib_path.c_str(), handle);
        }
    }

    if (handle) {
        // Standard path: we have a valid handle, use the existing pipeline
        il2cpp_api_init(handle);
        il2cpp_dump(game_data_dir);
    } else {
        // Fallback: no valid handle, but we have the base address from maps.
        // Use il2cpp_api_init_from_base() to resolve symbols by walking the
        // ELF from the mapped base address, and set il2cpp_base directly.
        LOGW("maps_scanner: all dlopen attempts failed, using base address fallback");
        LOGI("maps_scanner: calling il2cpp_api_init_from_base(0x%" PRIxPTR ")", base_addr);
        il2cpp_api_init_from_base(base_addr);
        il2cpp_dump(game_data_dir);
    }

    LOGI("maps_scanner: thread finished (tid=%d)", gettid());
}

// ---------------------------------------------------------------------------
// Original xdl_open based detection (kept as secondary fallback)
// ---------------------------------------------------------------------------

void hack_start(const char *game_data_dir) {
    bool load = false;
    for (int i = 0; i < 10; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            il2cpp_api_init(handle);
            il2cpp_dump(game_data_dir);
            break;
        } else {
            sleep(1);
        }
    }
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
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
    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        // Primary: use the /proc/self/maps scanner (bypasses broken dlopen hooks)
        LOGI("Starting /proc/self/maps scanner for libil2cpp.so detection");
        hack_start_maps(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    // Use maps scanner instead of the original hack_start
    std::thread hack_thread(hack_start_maps, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}

#endif
