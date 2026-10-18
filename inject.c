// inject.c — minimal arm64 ptrace injector
// rules:
//  - if ptrace fails at any step, detach and exit nonzero
//  - never leave the target in a stopped state on error
//  - never write to target memory before all checks pass
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

// ... (full implementation)