// inject.c — arm64 ptrace injector for Android
// usage: ./injector <pid> <path-to-so>
// safe: detaches on every error, never leaves target stopped
// dlopen resolved at runtime via ELF dynsym — no hardcoded offset

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <elf.h>

// ---------- maps parsing ----------

// find base address of a loaded library for pid
static unsigned long long find_lib_base(pid_t pid, const char* libname, char* out_path, size_t pathlen) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE* f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[1024];
    unsigned long long base = 0;
    while (fgets(line, sizeof(line), f)) {
        // format: start-end perms offset dev inode pathname
        unsigned long long start;
        char perms[8] = {0};
        char path[512] = {0};
        int matched = sscanf(line, "%llx-%*llx %7s %*s %*s %*s %511s",
                             &start, perms, path);
        if (matched < 3) continue;
        if (strstr(path, libname) && strchr(perms, 'r')) {
            base = start;
            if (out_path && pathlen) {
                strncpy(out_path, path, pathlen - 1);
                out_path[pathlen - 1] = 0;
            }
            break;
        }
    }
    fclose(f);
    return base;
}

// ---------- elf symbol resolution (host-side, reads libc file) ----------
// read libc.so from disk (on device), find dynsym entry for name, return st_value

static int resolve_symbol(const char* libpath, const char* symname, unsigned long long* out_addr) {
    FILE* f = fopen(libpath, "rb");
    if (!f) return -1;

    Elf64_Ehdr eh;
    if (fread(&eh, sizeof(eh), 1, f) != 1) { fclose(f); return -1; }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) { fclose(f); return -1; }
    if (eh.e_ident[EI_CLASS] != ELFCLASS64) { fclose(f); return -1; }

    // read program headers to find PT_DYNAMIC
    Elf64_Phdr ph;
    Elf64_Off dyn_off = 0;
    Elf64_Xword dyn_size = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (fseek(f, eh.e_phoff + i * sizeof(ph), SEEK_SET) != 0) { fclose(f); return -1; }
        if (fread(&ph, sizeof(ph), 1, f) != 1) { fclose(f); return -1; }
        if (ph.p_type == PT_DYNAMIC) {
            dyn_off = ph.p_offset;
            dyn_size = ph.p_filesz;
            break;
        }
    }
    if (!dyn_off) { fclose(f); return -1; }

    // read dynamic section
    size_t ndyn = dyn_size / sizeof(Elf64_Dyn);
    Elf64_Dyn* dyn = malloc(dyn_size);
    if (!dyn) { fclose(f); return -1; }
    if (fseek(f, dyn_off, SEEK_SET) != 0 || fread(dyn, dyn_size, 1, f) != 1) {
        free(dyn); fclose(f); return -1;
    }

    Elf64_Addr symtab_va = 0, strtab_va = 0;
    Elf64_Xword symtab_sz = 0, strtab_sz = 0;
    unsigned long hash_va = 0, gnu_hash_va = 0;

    for (size_t i = 0; i < ndyn && dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB:   symtab_va = dyn[i].d_un.d_ptr; break;
            case DT_STRTAB:   strtab_va = dyn[i].d_un.d_ptr; break;
            case DT_STRSZ:    strtab_sz = dyn[i].d_un.d_val; break;
            case DT_HASH:     hash_va   = dyn[i].d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash_va = dyn[i].d_un.d_ptr; break;
        }
    }
    free(dyn);
    if (!symtab_va || !strtab_va) { fclose(f); return -1; }

    // need to convert VA -> file offset via program headers
    // libc is mapped; its phdrs describe VA to offset
    // we re-read phdrs for mapping
    #define NPH 32
    Elf64_Phdr phs[NPH];
    int np = eh.e_phnum < NPH ? eh.e_phnum : NPH;
    for (int i = 0; i < np; i++) {
        fseek(f, eh.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
        fread(&phs[i], sizeof(Elf64_Phdr), 1, f);
    }

    #define VA2OFF(va, out) do { \
        (out) = 0; \
        for (int _i = 0; _i < np; _i++) { \
            if (phs[_i].p_type == PT_LOAD && \
                (va) >= phs[_i].p_vaddr && \
                (va) < phs[_i].p_vaddr + phs[_i].p_filesz) { \
                (out) = (va) - phs[_i].p_vaddr + phs[_i].p_offset; \
                break; \
            } \
        } \
    } while(0)

    // determine symbol count via hash or gnu_hash
    unsigned long nsyms = 0;
    if (hash_va) {
        unsigned long hash_off;
        VA2OFF(hash_va, hash_off);
        if (hash_off) {
            fseek(f, hash_off, SEEK_SET);
            unsigned int hdr[2];
            if (fread(hdr, sizeof(hdr), 1, f) == 1) nsyms = hdr[1];
        }
    }

    // if no DT_HASH, we need gnu_hash count — hard without parsing.
    // use symtab_sz fallback: DT_SYMTAB range unknown, but we can bound by
    // reading until symbol name match; safer is to estimate via strtab size.
    // for bionic libc, DT_HASH is usually present. if not, bail.
    if (!nsyms) { fclose(f); return -1; }

    unsigned long symtab_off, strtab_off;
    VA2OFF(symtab_va, symtab_off);
    VA2OFF(strtab_va, strtab_off);
    if (!symtab_off || !strtab_off) { fclose(f); return -1; }

    char namebuf[256];
    Elf64_Sym sym;
    for (unsigned long i = 0; i < nsyms; i++) {
        fseek(f, symtab_off + i * sizeof(Elf64_Sym), SEEK_SET);
        if (fread(&sym, sizeof(sym), 1, f) != 1) break;
        if (sym.st_name == 0) continue;
        fseek(f, strtab_off + sym.st_name, SEEK_SET);
        size_t n = fread(namebuf, 1, sizeof(namebuf) - 1, f);
        namebuf[n] = 0;
        if (strcmp(namebuf, symname) == 0) {
            *out_addr = sym.st_value;
            fclose(f);
            return 0;
        }
    }

    fclose(f);
    return -1;
}

// ---------- ptrace helpers ----------

static int attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) return -1;
    int status;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return 0;
}

static int detach(pid_t pid) {
    return ptrace(PTRACE_DETACH, pid, 0, 0);
}

static int getregs(pid_t pid, struct user_pt_regs* regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov);
}

static int setregs(pid_t pid, struct user_pt_regs* regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
}

// write a string into target stack via POKEDATA (word-at-a-time)
static int write_str(pid_t pid, unsigned long long addr, const char* s, size_t len) {
    size_t i = 0;
    while (i < len) {
        unsigned long long word = 0;
        size_t n = (len - i) < 8 ? (len - i) : 8;
        memcpy(&word, s + i, n);
        if (ptrace(PTRACE_POKEDATA, pid, (void*)(addr + i), (void*)word) < 0) {
            return -1;
        }
        i += 8;
    }
    return 0;
}

// ---------- main ----------

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

    struct user_pt_regs saved, regs;
    if (getregs(pid, &saved) < 0) {
        fprintf(stderr, "getregs failed\n");
        detach(pid);
        return 1;
    }
    regs = saved;

    // find libc path and base
    char libc_path[512] = {0};
    unsigned long long libc_base = find_lib_base(pid, "libc.so", libc_path, sizeof(libc_path));
    if (!libc_base) {
        fprintf(stderr, "libc.so not found in maps\n");
        detach(pid);
        return 1;
    }
    fprintf(stderr, "libc base: 0x%llx  (%s)\n", libc_base, libc_path);

    // resolve dlopen offset from the on-disk libc file
    unsigned long long dlopen_off = 0;
    if (resolve_symbol(libc_path, "dlopen", &dlopen_off) < 0) {
        fprintf(stderr, "dlopen symbol not resolved from %s\n", libc_path);
        detach(pid);
        return 1;
    }
    unsigned long long dlopen_addr = libc_base + dlopen_off;
    fprintf(stderr, "dlopen offset: 0x%llx  -> addr 0x%llx\n", dlopen_off, dlopen_addr);

    // write path string into target stack
    size_t len = strlen(so_path) + 1;
    unsigned long long scratch = regs.sp - 0x2000; // below sp, safe scratch
    if (write_str(pid, scratch, so_path, len) < 0) {
        fprintf(stderr, "write path failed\n");
        detach(pid);
        return 1;
    }

    // set up call: dlopen(path, RTLD_NOW)
    regs.regs[0] = scratch;      // x0 = path
    regs.regs[1] = 2;            // x1 = RTLD_NOW
    regs.regs[30] = 0;           // x30 (lr) = 0, so if it returns to 0 it faults and we catch it
    regs.pc = dlopen_addr;

    if (setregs(pid, &regs) < 0) {
        fprintf(stderr, "setregs failed\n");
        detach(pid);
        return 1;
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
        fprintf(stderr, "cont failed\n");
        detach(pid);
        return 1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "waitpid failed\n");
        detach(pid);
        return 1;
    }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "target didn't stop (status=0x%x)\n", status);
        detach(pid);
        return 1;
    }

    // read return value
    if (getregs(pid, &regs) < 0) {
        fprintf(stderr, "getregs after call failed\n");
    } else {
        fprintf(stderr, "dlopen returned: 0x%llx\n", (unsigned long long)regs.regs[0]);
    }

    // restore
    setregs(pid, &saved);
    detach(pid);

    return (regs.regs[0] != 0) ? 0 : 2;
}