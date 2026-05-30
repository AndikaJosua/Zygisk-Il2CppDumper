//
// Created by Perfare on 2020/7/4.
//
// Modified: Added stable /proc/self/maps scanner to bypass failing dlopen/NativeBridge hooks
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

static void hack_start_maps() {
    LOGI("Perfare: Detached background maps scanning thread successfully spun up (tid=%d).", gettid());

    // Hardcoded package path to bypass unverified pointer passing in emulator translation layers
    const char *game_data_dir = "/data/data/com.kukouri.wizworld/files";
    unsigned int loop_count = 0;
    uintptr_t base_addr = 0;

    constexpr auto POLL_INTERVAL = std::chrono::milliseconds(500);

    while (true) {
        loop_count++;
        LOGI("Perfare: Scanning iteration loop running (loop_count=%u)...", loop_count);

        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) {
            LOGE("Perfare: [ERROR] Failed to open /proc/self/maps on iteration %u.", loop_count);
            std::this_thread::sleep_for(POLL_INTERVAL);
            continue;
        }

        std::string line;
        bool found_base = false;

        while (std::getline(maps, line)) {
            if (line.find("libil2cpp.so") == std::string::npos) {
                continue;
            }

            LOGI("Perfare: Found string 'libil2cpp.so' in maps line: %s", line.c_str());

            // Verify segment execution/read permissions
            size_t address_end = line.find(' ');
            if (address_end == std::string::npos) continue;

            size_t perms_start = address_end;
            while (perms_start < line.length() && line[perms_start] == ' ') {
                perms_start++;
            }

            if (perms_start + 4 > line.length()) continue;

            std::string perms = line.substr(perms_start, 4);
            if (perms != "r-xp" && perms != "r--p") {
                LOGI("Perfare: Skipping segment with permissions: %s", perms.c_str());
                continue;
            }

            size_t dash = line.find('-');
            if (dash == std::string::npos || dash > address_end) continue;

            std::string start_addr_str = line.substr(0, dash);
            if (start_addr_str.empty()) continue;

            // Hex check
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
                LOGE("Perfare: strtoull parsing failed for address string: %s", start_addr_str.c_str());
                continue;
            }

            base_addr = static_cast<uintptr_t>(parsed_val);
            LOGI("Perfare: SUCCESS! Memory address parsed cleanly: 0x%llx", (unsigned long long)base_addr);
            found_base = true;
            break;
        }

        maps.close();

        if (found_base && base_addr != 0) {
            break;
        }

        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    // Secondary Stabilization Validation: Ensure symbols are fully loaded by the engine before dump
    LOGI("Perfare: Waiting for library symbol initialization stability...");
    void* handle = nullptr;
    while (handle == nullptr) {
        handle = dlopen("libil2cpp.so", RTLD_LAZY);
        if (handle == nullptr) {
            // Fallback check via absolute path if standard dlopen is isolated
            handle = dlopen("/data/app/com.kukouri.wizworld-1/lib/arm64/libil2cpp.so", RTLD_LAZY);
        }
        if (handle != nullptr) {
            void* init_sym = dlsym(handle, "il2cpp_init");
            if (init_sym == nullptr) {
                dlclose(handle);
                handle = nullptr;
            }
        }
        if (handle == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    dlclose(handle);

    LOGI("Perfare: Library verified stable. Executing dump at base 0x%llx...", (unsigned long long)base_addr);
    il2cpp_api_init_from_base(base_addr);
    il2cpp_dump(game_data_dir);
    LOGI("Perfare: Core dumper extraction completed cleanly!");
}

// ---------------------------------------------------------------------------
// JNI / NativeBridge setups (unchanged)
// ---------------------------------------------------------------------------

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application, get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(env->GetObjectClass(application_info), "nativeLibraryDir", "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    }
                }
            }
        }
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
    sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) {
        vms = vms_buf[0];
    } else {
        return false;
    }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) {
        munmap(data, length);
        return false;
    }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }
    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);

            void *arm_handle;
            if (api_level >= 26) {
                arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3);
            } else {
                arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
            }
            if (arm_handle) {
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                init(vms, (void *) game_data_dir);
                return true;
            }
            close(fd);
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Entry point dispatches
// ---------------------------------------------------------------------------

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("Perfare: hack_prepare entry point triggered.");
    int api_level = android_get_device_api_level();

#if defined(__i386__) || defined(__x86_64__)
    if (NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        LOGI("Perfare: Context passed through translation layer successfully.");
        return;
    }
#endif

    std::thread(hack_start_maps).detach();
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("Perfare: ARM translator context intercepted inside JNI_OnLoad.");
    std::thread(hack_start_maps).detach();
    return JNI_VERSION_1_6;
}
#endif
