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
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dirent.h>
#include <string>
#include <vector>
#include <android/log.h>
#include <android/dlext.h>
#include <elf.h>
#include <sys/user.h>

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

static bool inject_via_ptrace(int pid, const char* lib_path, uintptr_t dlopen_addr) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        LOGE("PTRACE_ATTACH failed: %s", strerror(errno));
        return false;
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        LOGE("waitpid failed");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }

    struct user_pt_regs regs;
    struct iovec iov = { &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        LOGE("PTRACE_GETREGSET failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    struct user_pt_regs saved_regs = regs;

    uintptr_t sp = regs.sp;
    uintptr_t path_addr = sp - 0x1000;

    if (!process_vm_write(pid, path_addr, lib_path, strlen(lib_path) + 1)) {
        LOGE("Cannot write path to remote memory");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }

    regs.regs[0] = path_addr;
    regs.regs[1] = RTLD_NOW;
    regs.pc = dlopen_addr;
    regs.regs[30] = 0;

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov) < 0) {
        LOGE("PTRACE_SETREGSET failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        LOGE("PTRACE_CONT failed");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }

    int sig = 0;
    if (waitpid(pid, &status, 0) < 0) {
        LOGE("waitpid after cont failed");
    } else if (WIFSTOPPED(status)) {
        sig = WSTOPSIG(status);
        LOGI("Process stopped with signal %d", sig);
    }

    iov.iov_base = &saved_regs;
    iov.iov_len = sizeof(saved_regs);
    ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    LOGI("Detached from process");
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

    uintptr_t dlopen_addr = get_remote_symbol(pid, "libdl.so", "dlopen");
    if (!dlopen_addr) {
        LOGE("Cannot resolve remote dlopen");
        return 1;
    }
    LOGI("Remote dlopen: 0x%lx", (unsigned long)dlopen_addr);

    if (!inject_via_ptrace(pid, lib_path, dlopen_addr)) {
        LOGE("Injection failed");
        return 1;
    }

    LOGI("Injection succeeded");
    return 0;
}
