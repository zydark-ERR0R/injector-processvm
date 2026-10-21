#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string>
#include <vector>
#include <android/log.h>
#include <android/dlext.h>

#include "shellcode.h"

#define LOG_TAG "PVMInjector"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static int find_pid(const char* package) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_type != DT_DIR) continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        int fd = open(cmdline_path, O_RDONLY);
        if (fd < 0) continue;

        char buf[256] = {0};
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);

        if (n > 0 && strstr(buf, package)) {
            closedir(dir);
            return pid;
        }
    }
    closedir(dir);
    return -1;
}

static uintptr_t get_remote_symbol(int pid, const char* lib_name, const char* sym_name) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) return 0;

    uintptr_t base = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, lib_name) && strstr(line, "r-xp")) {
            base = strtoull(line, nullptr, 16);
            break;
        }
    }
    fclose(fp);
    if (!base) return 0;

    void* local_handle = dlopen(lib_name, RTLD_LAZY);
    if (!local_handle) return 0;
    void* local_sym = dlsym(local_handle, sym_name);
    if (!local_sym) { dlclose(local_handle); return 0; }

    Dl_info info;
    if (!dladdr(local_sym, &info)) { dlclose(local_handle); return 0; }
    uintptr_t local_base = (uintptr_t)info.dli_fbase;
    dlclose(local_handle);

    return base + ((uintptr_t)local_sym - local_base);
}

static bool process_vm_write(int pid, uintptr_t addr, const void* data, size_t len) {
    struct iovec local = { const_cast<void*>(data), len };
    struct iovec remote = { reinterpret_cast<void*>(addr), len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    return n == (ssize_t)len;
}

static uintptr_t get_remote_pc(int pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
    FILE* fp = fopen(path, "r");
    if (!fp) return 0;
    long long pc = 0;
    if (fscanf(fp, "%*d %*d %lld", &pc) != 1) pc = 0;
    fclose(fp);
    return (uintptr_t)pc;
}

static bool inject_library(int pid, const char* lib_path) {
    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) {
        LOGE("Cannot open %s: %s", lib_path, strerror(errno));
        return false;
    }

    struct stat st;
    fstat(fd, &st);
    if (st.st_size <= 0 || st.st_size > 64 * 1024 * 1024) {
        close(fd);
        return false;
    }

    std::vector<uint8_t> lib_data(st.st_size);
    ssize_t total = 0;
    while (total < st.st_size) {
        ssize_t n = read(fd, lib_data.data() + total, st.st_size - total);
        if (n <= 0) { close(fd); return false; }
        total += n;
    }
    close(fd);

    uintptr_t dlopen_addr = get_remote_symbol(pid, "libdl.so", "dlopen");
    uintptr_t restore_addr = get_remote_pc(pid);

    if (!dlopen_addr) {
        LOGE("Cannot resolve remote dlopen");
        return false;
    }
    if (!restore_addr) {
        LOGE("Cannot get remote PC");
        return false;
    }

    LOGI("Remote dlopen: 0x%lx", (unsigned long)dlopen_addr);
    LOGI("Remote PC: 0x%lx", (unsigned long)restore_addr);

    uintptr_t memfd_addr = restore_addr + 0x1000;
    uintptr_t shellcode_addr = restore_addr + 0x2000;
    uintptr_t path_addr = restore_addr + 0x3000;
    uintptr_t result_addr = restore_addr + 0x4000;

    uint8_t original_code[64];
    struct iovec local_read = { original_code, sizeof(original_code) };
    struct iovec remote_read = { reinterpret_cast<void*>(restore_addr), sizeof(original_code) };
    if (process_vm_readv(pid, &local_read, 1, &remote_read, 1, 0) != sizeof(original_code)) {
        LOGE("Cannot read original code");
        return false;
    }

    ShellcodeContext ctx = {
        dlopen_addr,
        dlopen_addr,
        restore_addr,
        path_addr,
        result_addr
    };

    uint8_t shellcode_buf[512];
    build_shellcode(shellcode_buf, ctx);

    if (!process_vm_write(pid, shellcode_addr, shellcode_buf, sizeof(shellcode_buf))) {
        LOGE("Cannot write shellcode");
        return false;
    }

    if (!process_vm_write(pid, path_addr, lib_path, strlen(lib_path) + 1)) {
        LOGE("Cannot write path");
        return false;
    }

    if (!process_vm_write(pid, restore_addr, shellcode_buf, 32)) {
        LOGE("Cannot write shellcode to PC");
        return false;
    }

    LOGI("Shellcode injected, waiting for execution...");
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        LOGE("Usage: %s <package> <lib_path>", argv[0]);
        return 1;
    }

    const char* package = argv[1];
    const char* lib_path = argv[2];

    LOGI("Target: %s", package);
    LOGI("Library: %s", lib_path);

    int pid = find_pid(package);
    if (pid <= 0) {
        LOGE("Process not found: %s", package);
        return 1;
    }

    LOGI("Found PID: %d", pid);

    if (!inject_library(pid, lib_path)) {
        LOGE("Injection failed");
        return 1;
    }

    LOGI("Injection succeeded");
    return 0;
}
