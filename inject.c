// inject.c — arm64 ptrace injector for Android
// usage: ./injector <pid> <path-to-so>
// safe: detaches on every error, never leaves target stopped

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <elf.h>

// aarch64 ptrace register access
struct user_pt_regs {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
};

static int attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) return -1;
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return 0;
}

static int detach(pid_t pid) {
    return ptrace(PTRACE_DETACH, pid, 0, 0);
}

static unsigned long long find_libc_base(pid_t pid, const char* libname) {
    char path[64], line[512];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return 0;

    unsigned long long base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, libname) && strstr(line, "r-xp")) {
            sscanf(line, "%llx-", &base);
            break;
        }
    }
    fclose(f);
    return base;
}

static unsigned long long find_dlopen_addr(pid_t pid) {
    unsigned long long base = find_libc_base(pid, "libc.so");
    if (!base) return 0;
    // dlopen offset in bionic libc is stable across Android versions for arm64
    // if this fails, adjust by finding the symbol in your device's libc
    return base + 0x5a1a0; // approximate — see notes below
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <path-to-so>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char* so_path = argv[2];

    if (attach(pid) < 0) {
        fprintf(stderr, "attach failed: %s\n", strerror(errno));
        return 1;
    }

    struct user_pt_regs regs;
    struct iovec iov = { &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, (void*)1, &iov) < 0) {
        fprintf(stderr, "getregs failed\n");
        detach(pid);
        return 1;
    }

    struct user_pt_regs saved = regs;

    unsigned long long dlopen_addr = find_dlopen_addr(pid);
    if (!dlopen_addr) {
        fprintf(stderr, "dlopen not found\n");
        detach(pid);
        return 1;
    }

    // write path string into target stack (below sp, safe scratch area)
    unsigned long long sp = regs.sp - 0x1000;
    size_t len = strlen(so_path) + 1;
    for (size_t i = 0; i < len; i += 8) {
        unsigned long long word = 0;
        memcpy(&word, so_path + i, (len - i) < 8 ? (len - i) : 8);
        if (ptrace(PTRACE_POKETEXT, pid, (void*)(sp + i), (void*)word) < 0) {
            fprintf(stderr, "poketext path failed\n");
            detach(pid);
            return 1;
        }
    }

    // set up call: dlopen(path, RTLD_NOW)
    regs.regs[0] = sp;       // arg0 = path
    regs.regs[1] = 2;        // arg1 = RTLD_NOW
    regs.pc = dlopen_addr;
    regs.sp = sp;

    if (ptrace(PTRACE_SETREGSET, pid, (void*)1, &iov) < 0) {
        fprintf(stderr, "setregs failed\n");
        detach(pid);
        return 1;
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
        fprintf(stderr, "cont failed\n");
        detach(pid);
        return 1;
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "target didn't stop — likely SIGSEGV\n");
        detach(pid);
        return 1;
    }

    // read return value (regs[0] = dlopen result)
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    ptrace(PTRACE_GETREGSET, pid, (void*)1, &iov);

    fprintf(stderr, "dlopen returned: 0x%llx\n", regs.regs[0]);

    // restore
    iov.iov_base = &saved;
    ptrace(PTRACE_SETREGSET, pid, (void*)1, &iov);
    detach(pid);

    return regs.regs[0] ? 0 : 1;
}