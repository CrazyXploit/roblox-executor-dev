// host.c — Roblox executor host
// compiled as libexecutor.so, injected via ptrace into com.roblox.client
// responsibilities:
//   1. write a proof-of-life log
//   2. spawn a unix-socket thread that accepts Lua source, runs it in Luau
//   3. expose print / warn / loadstring / getgenv / setclipboard-ish stubs
// does NOT touch system files, does NOT hook anything, does NOT alter Roblox.

#include "lua.h"
#include "lualib.h"
#include "luacode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SOCK_PATH   "/data/local/tmp/executor.sock"
#define LOG_PATH    "/sdcard/executor_injected.log"
#define RX_MAX      (1 * 1024 * 1024)   // 1 MB max script size
#define OUT_MAX     (256 * 1024)        // 256 KB max return buffer

// ---------------- output capture ----------------
// we route luau print into a per-call buffer so the termux client sees output
// without touching stdout (which Roblox owns)

typedef struct {
    char*  buf;
    size_t len;
    size_t cap;
} outbuf_t;

static void out_init(outbuf_t* o) {
    o->cap = 4096;
    o->len = 0;
    o->buf = (char*)malloc(o->cap);
    if (o->buf) o->buf[0] = 0;
}

static void out_free(outbuf_t* o) {
    free(o->buf);
    o->buf = NULL;
    o->len = o->cap = 0;
}

static void out_append(outbuf_t* o, const char* s, size_t n) {
    if (!o->buf) return;
    if (o->len + n + 1 > o->cap) {
        size_t nc = o->cap ? o->cap : 4096;
        while (nc < o->len + n + 1) nc *= 2;
        if (nc > OUT_MAX) nc = OUT_MAX;
        if (nc <= o->len) return; // saturated, drop
        char* nb = (char*)realloc(o->buf, nc);
        if (!nb) return;
        o->buf = nb;
        o->cap = nc;
    }
    size_t room = o->cap - o->len - 1;
    if (n > room) n = room;
    memcpy(o->buf + o->len, s, n);
    o->len += n;
    o->buf[o->len] = 0;
}

// per-thread current outbuf (execution is single-threaded per connection)
static __thread outbuf_t* g_out = NULL;

// ---------------- luau bindings ----------------

static int l_print(lua_State* L) {
    int n = lua_gettop(L);
    outbuf_t* o = g_out;
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len);
        if (o && s) {
            out_append(o, s, len);
            if (i < n) out_append(o, "\t", 1);
        }
        lua_pop(L, 1);
    }
    if (o) out_append(o, "\n", 1);
    return 0;
}

static int l_warn(lua_State* L) {
    int n = lua_gettop(L);
    outbuf_t* o = g_out;
    if (o) out_append(o, "[warn] ", 7);
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len);
        if (o && s) {
            out_append(o, s, len);
            if (i < n) out_append(o, "\t", 1);
        }
        lua_pop(L, 1);
    }
    if (o) out_append(o, "\n", 1);
    return 0;
}

static int l_getgenv(lua_State* L) {
    // return the globals table — executors expose this so scripts can share state
    lua_pushvalue(L, LUA_GLOBALSINDEX);
    return 1;
}

static int l_loadstring(lua_State* L) {
    size_t len = 0;
    const char* src = luaL_checklstring(L, 1, &len);
    if (luau_load(L, "=loadstring", src, len, 0) != LUA_OK) {
        lua_pushnil(L);
        lua_insert(L, -2);
        return 2;
    }
    return 1;
}

// weak placeholder — real executor would push to Roblox clipboard API
static int l_setclipboard(lua_State* L) {
    size_t len = 0;
    const char* s = luaL_checklstring(L, 1, &len);
    outbuf_t* o = g_out;
    if (o) {
        out_append(o, "[setclipboard] ", 15);
        out_append(o, s, len);
        out_append(o, "\n", 1);
    }
    return 0;
}

static int l_identifyexecutor(lua_State* L) {
    lua_pushstring(L, "DotbhaiExecutor-Dev");
    lua_pushstring(L, "1.0-dev");
    return 2;
}

// ---------------- script runner ----------------

static void run_script(const char* src, size_t len, outbuf_t* out) {
    lua_State* L = luaL_newstate();
    if (!L) {
        out_append(out, "[fatal] luaL_newstate failed\n", 28);
        return;
    }
    luaL_openlibs(L);

    lua_register(L, "print", l_print);
    lua_register(L, "warn", l_warn);
    lua_register(L, "getgenv", l_getgenv);
    lua_register(L, "loadstring", l_loadstring);
    lua_register(L, "setclipboard", l_setclipboard);
    lua_register(L, "identifyexecutor", l_identifyexecutor);

    // fake game/workspace stubs so top-level scripts don't nil-error
    // (real bridge to Roblox memory is a separate project)
    const char* stubs =
        "game = game or {}\n"
        "workspace = workspace or {}\n"
        "Players = Players or {}\n";
    luau_load(L, "=stubs", stubs, strlen(stubs), 0);
    lua_pcall(L, 0, 0, 0);

    outbuf_t* prev = g_out;
    g_out = out;

    if (luau_load(L, "=script", src, len, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        if (err) {
            out_append(out, "[compile error] ", 16);
            out_append(out, err, strlen(err));
            out_append(out, "\n", 1);
        }
    } else {
        if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
            const char* err = lua_tostring(L, -1);
            if (err) {
                out_append(out, "[runtime error] ", 16);
                out_append(out, err, strlen(err));
                out_append(out, "\n", 1);
            }
        } else {
            out_append(out, "[ok]\n", 5);
        }
    }

    g_out = prev;
    lua_close(L);
}

// ---------------- socket server ----------------

static ssize_t read_all(int fd, char* buf, size_t cap) {
    size_t total = 0;
    while (total < cap - 1) {
        ssize_t n = read(fd, buf + total, cap - 1 - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    buf[total] = 0;
    return (ssize_t)total;
}

static void handle_client(int c) {
    char* rx = (char*)malloc(RX_MAX);
    if (!rx) { close(c); return; }

    ssize_t n = read_all(c, rx, RX_MAX);
    if (n <= 0) { free(rx); close(c); return; }

    outbuf_t out;
    out_init(&out);
    run_script(rx, (size_t)n, &out);

    if (out.buf) {
        size_t off = 0;
        while (off < out.len) {
            ssize_t w = write(c, out.buf + off, out.len - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
    }
    out_free(&out);
    free(rx);
    close(c);
}

static void* server_main(void* arg) {
    (void)arg;

    unlink(SOCK_PATH);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return NULL;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return NULL;
    }
    chmod(SOCK_PATH, 0666);

    if (listen(fd, 4) < 0) {
        close(fd);
        return NULL;
    }

    for (;;) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR) continue;
            break;
        }
        handle_client(c);
    }

    close(fd);
    unlink(SOCK_PATH);
    return NULL;
}

// ---------------- constructor ----------------

__attribute__((constructor))
static void executor_init(void) {
    // proof-of-life log — tells us injection worked
    FILE* f = fopen(LOG_PATH, "w");
    if (f) {
        fprintf(f, "injected pid=%d\n", (int)getpid());
        fclose(f);
    }

    pthread_t t;
    if (pthread_create(&t, NULL, server_main, NULL) == 0) {
        pthread_detach(t);
    }
}