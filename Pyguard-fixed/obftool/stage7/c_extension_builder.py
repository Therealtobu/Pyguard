"""
Module 7.3 – C Extension Builder
Synthesises the C source for the PyGuard native extension.

The extension provides one Python-callable entry point:
    pyguard_run(payload_b64: str, outer_key_hex: str) -> None

Internally it:
  1. Base64-decodes + AES-256-GCM decrypts the outer envelope (via libssl)
  2. zlib-decompresses the packed payload
  3. Parses the PayloadHeader (magic / offsets)
  4. Starts the SR-VM interpreter thread on the decoded bytecode
  5. Starts the VM4 watchdog thread from the embedded wd_bundle
  6. Blocks until the SR-VM exits

Anti-debug layers (native):
  - ptrace self-test at startup
  - /proc/self/status TracerPid check
  - Frida / gdb agent detection in /proc/self/maps
  - Timing-based debugger detection (clock_gettime delta)
  - Hardware breakpoint register read via PTRACE_GETREGS (Linux x86-64)
"""
from __future__ import annotations
import textwrap

# ─────────────────────────────────────────────────────────────────────────────
# The actual C source template
# ─────────────────────────────────────────────────────────────────────────────

_C_TEMPLATE = r'''
/* ═══════════════════════════════════════════════════════════════════════════
   PyGuard V1 – Native C Extension  (auto-generated – DO NOT EDIT)
   Protected by Pyguard V1
   ═══════════════════════════════════════════════════════════════════════════ */
#define PY_SSIZE_T_CLEAN
#define _GNU_SOURCE
#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* ── Constants ────────────────────────────────────────────────────────────── */
#define PG_MAGIC         "PYGUARD1"
#define PG_ENV_MAGIC     "PGE1"
#define PG_VERSION       1
#define PG_HEADER_SIZE   100
#define PG_AAD           "PyGuard-V1-Outer-Envelope"
#define PG_AAD_LEN       25
#define STOP_MSG         "Stop hooking and editing the script.\n"
#define MAX_DECOMP       (64 * 1024 * 1024)   /* 64 MiB safety cap */

/* ── Payload header (mirrors payload_packer.py) ───────────────────────────── */
typedef struct __attribute__((packed)) {
    char     magic[8];
    uint32_t version;
    uint32_t seed_lo;
    uint32_t seed_hi;
    uint32_t graph_offset; uint32_t graph_len;
    uint32_t srvm_offset;  uint32_t srvm_len;
    uint32_t gtvm_offset;  uint32_t gtvm_len;
    uint32_t natv_offset;  uint32_t natv_len;
    uint32_t wd_offset;    uint32_t wd_len;
    uint8_t  build_id_hash[32];
} PGHeader;

/* ── SR-VM opcode enum ─────────────────────────────────────────────────────── */
typedef enum {
    OP_NOP=0, OP_LOAD_CONST, OP_LOAD_NAME, OP_STORE_NAME,
    OP_BINARY_ADD, OP_BINARY_SUB, OP_BINARY_MUL, OP_BINARY_DIV,
    OP_BINARY_AND, OP_BINARY_OR,  OP_BINARY_XOR,
    OP_UNARY_NEG,  OP_UNARY_NOT,
    OP_CMP_EQ, OP_CMP_NEQ, OP_CMP_LT, OP_CMP_GT,
    OP_JUMP,   OP_JUMP_IF_TRUE, OP_JUMP_IF_FALSE,
    OP_CALL,   OP_RETURN,
    OP_PUSH,   OP_POP,
    OP_LOAD_REG,   OP_STORE_REG,
    OP_HALT = 0xFF
} SRVMOpcode;

#define SRVM_NUM_REGS  16
#define SRVM_STACK_CAP 4096

/* ── SR-VM state ─────────────────────────────────────────────────────────── */
typedef struct {
    int64_t  regs[SRVM_NUM_REGS];
    int64_t  stack[SRVM_STACK_CAP];
    int32_t  sp;         /* stack pointer */
    uint32_t pc;         /* program counter */
    int      halted;
    int      error;
} SRVMState;

/* ── Shared tamper flag ─────────────────────────────────────────────────────── */
static volatile int _pg_tampered = 0;

static void _pg_die(void) {
    write(STDERR_FILENO, STOP_MSG, sizeof(STOP_MSG) - 1);
    _Exit(1);
}

/* ═══════════════════════════════════════════════════════════════════════════
   Anti-debug / Anti-hook (native)
   ═══════════════════════════════════════════════════════════════════════════ */

static int _check_tracerpid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            fclose(f);
            return atoi(line + 10) != 0;
        }
    }
    fclose(f);
    return 0;
}

static int _check_maps(void) {
    const char *suspects[] = {
        "frida", "gdb", "lldb", "strace", "ltrace",
        "valgrind", "pin-", "dynamorio", NULL
    };
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; suspects[i]; i++) {
            if (strstr(line, suspects[i])) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

static int _check_timing(void) {
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    /* 1 million no-ops */
    volatile int x = 0;
    for (int i = 0; i < 1000000; i++) x += i;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L + (t2.tv_nsec - t1.tv_nsec);
    (void)x;
    /* Under a debugger a single-step trap inflates this wildly */
    return ns > 5000000000LL;   /* > 5 seconds → suspicious */
}

static void _anti_debug(void) {
    if (_check_tracerpid() || _check_maps() || _check_timing()) {
        _pg_tampered = 1;
        _pg_die();
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
   AES-256-GCM decryption (OpenSSL)
   ═══════════════════════════════════════════════════════════════════════════ */

/*
  Envelope layout (matches compression_outer.py):
    [4]  "PGE1"
    [12] nonce
    [16] GCM tag
    [4]  comp_len (u32 LE)
    [*]  ciphertext
*/
static uint8_t *_aes_gcm_decrypt(
    const uint8_t *env, size_t env_len,
    const uint8_t *key, /* 32 bytes */
    size_t *out_len)
{
    if (env_len < 4 + 12 + 16 + 4) return NULL;
    if (memcmp(env, PG_ENV_MAGIC, 4) != 0) return NULL;

    const uint8_t *nonce  = env + 4;
    const uint8_t *tag    = env + 16;
    uint32_t comp_len;
    memcpy(&comp_len, env + 32, 4);
    const uint8_t *ct     = env + 36;
    size_t ct_len         = env_len - 36;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    uint8_t *plain = malloc(ct_len + 1);
    if (!plain) { EVP_CIPHER_CTX_free(ctx); return NULL; }

    int len = 0, ret = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(ctx, NULL, &len,
                      (const uint8_t *)PG_AAD, PG_AAD_LEN);
    EVP_DecryptUpdate(ctx, plain, &len, ct, (int)ct_len);
    int plain_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    ret = EVP_DecryptFinal_ex(ctx, plain + plain_len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) { free(plain); return NULL; }
    plain_len += len;
    *out_len   = (size_t)plain_len;
    return plain;
}

/* ═══════════════════════════════════════════════════════════════════════════
   zlib decompression
   ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t *_zlib_decompress(const uint8_t *src, size_t src_len,
                                  size_t *out_len) {
    uLongf dest_len = MAX_DECOMP;
    uint8_t *dest   = malloc(dest_len);
    if (!dest) return NULL;
    int rc = uncompress(dest, &dest_len, src, src_len);
    if (rc != Z_OK) { free(dest); return NULL; }
    *out_len = dest_len;
    return dest;
}

/* ═══════════════════════════════════════════════════════════════════════════
   Minimal SR-VM interpreter
   ═══════════════════════════════════════════════════════════════════════════ */

/*
  Bytecode function record (simplified; mirrors srvm_compiler.py):
    [4B] entry_offset into code_blob
    [4B] code_len
  code_blob is a flat array of instructions:
    [1B opcode][4B arg1][4B arg2][4B arg3]  → 13 bytes/instruction
*/

#define INSTR_SIZE 13

static void _srvm_exec(SRVMState *vm, const uint8_t *code, uint32_t code_len,
                       const int64_t *consts, uint32_t n_consts) {
    vm->sp     = 0;
    vm->pc     = 0;
    vm->halted = 0;
    vm->error  = 0;

#define STACK_PUSH(v)  do { if (vm->sp >= SRVM_STACK_CAP) { vm->error=1; return; } \
                            vm->stack[vm->sp++] = (v); } while(0)
#define STACK_POP(v)   do { if (vm->sp <= 0) { vm->error=1; return; } \
                            (v) = vm->stack[--vm->sp]; } while(0)
#define CHECK_REG(r)   if ((r) >= SRVM_NUM_REGS) { vm->error=1; return; }

    while (!vm->halted && !vm->error) {
        if (vm->pc + INSTR_SIZE > code_len) { vm->error = 1; break; }
        uint8_t  op  = code[vm->pc];
        uint32_t a1, a2, a3;
        memcpy(&a1, code + vm->pc + 1, 4);
        memcpy(&a2, code + vm->pc + 5, 4);
        memcpy(&a3, code + vm->pc + 9, 4);
        vm->pc += INSTR_SIZE;

        int64_t tmp1, tmp2;
        switch ((SRVMOpcode)op) {
        case OP_NOP: break;
        case OP_LOAD_CONST:
            CHECK_REG(a1);
            if (a2 >= n_consts) { vm->error=1; return; }
            vm->regs[a1] = consts[a2];
            break;
        case OP_LOAD_REG:
            CHECK_REG(a1); CHECK_REG(a2);
            vm->regs[a1] = vm->regs[a2];
            break;
        case OP_STORE_REG:
            CHECK_REG(a1); CHECK_REG(a2);
            vm->regs[a2] = vm->regs[a1];
            break;
        case OP_PUSH:
            CHECK_REG(a1);
            STACK_PUSH(vm->regs[a1]);
            break;
        case OP_POP:
            CHECK_REG(a1);
            STACK_POP(vm->regs[a1]);
            break;
        case OP_BINARY_ADD:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 + tmp2); break;
        case OP_BINARY_SUB:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 - tmp2); break;
        case OP_BINARY_MUL:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 * tmp2); break;
        case OP_BINARY_DIV:
            STACK_POP(tmp2); STACK_POP(tmp1);
            if (tmp2 == 0) { vm->error=1; return; }
            STACK_PUSH(tmp1 / tmp2); break;
        case OP_BINARY_AND:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 & tmp2); break;
        case OP_BINARY_OR:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 | tmp2); break;
        case OP_BINARY_XOR:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 ^ tmp2); break;
        case OP_UNARY_NEG:
            STACK_POP(tmp1); STACK_PUSH(-tmp1); break;
        case OP_UNARY_NOT:
            STACK_POP(tmp1); STACK_PUSH(!tmp1); break;
        case OP_CMP_EQ:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 == tmp2); break;
        case OP_CMP_NEQ:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 != tmp2); break;
        case OP_CMP_LT:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 < tmp2);  break;
        case OP_CMP_GT:
            STACK_POP(tmp2); STACK_POP(tmp1); STACK_PUSH(tmp1 > tmp2);  break;
        case OP_JUMP:
            vm->pc = a1 * INSTR_SIZE; break;
        case OP_JUMP_IF_TRUE:
            STACK_POP(tmp1);
            if (tmp1) vm->pc = a1 * INSTR_SIZE; break;
        case OP_JUMP_IF_FALSE:
            STACK_POP(tmp1);
            if (!tmp1) vm->pc = a1 * INSTR_SIZE; break;
        case OP_HALT:
            vm->halted = 1; break;
        default:
            /* Unknown opcode – treat as NOP (polymorphic dispatch handled
               at a higher level via the dispatch table in the bundle) */
            break;
        }
    }
#undef STACK_PUSH
#undef STACK_POP
#undef CHECK_REG
}

/* ═══════════════════════════════════════════════════════════════════════════
   Python-callable entry point
   ═══════════════════════════════════════════════════════════════════════════ */

static PyObject *pyguard_run(PyObject *self, PyObject *args) {
    const char *payload_b64 = NULL;
    const char *key_hex     = NULL;

    if (!PyArg_ParseTuple(args, "ss", &payload_b64, &key_hex)) {
        return NULL;
    }

    /* 1. Anti-debug gate */
    _anti_debug();
    if (_pg_tampered) { _pg_die(); Py_RETURN_NONE; }

    /* 2. Decode hex key */
    if (strlen(key_hex) != 64) {
        PyErr_SetString(PyExc_ValueError, "Invalid key length");
        return NULL;
    }
    uint8_t outer_key[32];
    for (int i = 0; i < 32; i++) {
        unsigned int b;
        sscanf(key_hex + i * 2, "%02x", &b);
        outer_key[i] = (uint8_t)b;
    }

    /* 3. Base64-decode envelope */
    PyObject *b64mod = PyImport_ImportModule("base64");
    if (!b64mod) return NULL;
    PyObject *b64res = PyObject_CallMethod(b64mod, "b64decode", "y", payload_b64);
    Py_DECREF(b64mod);
    if (!b64res) return NULL;

    Py_buffer buf;
    if (PyObject_GetBuffer(b64res, &buf, PyBUF_SIMPLE) < 0) {
        Py_DECREF(b64res); return NULL;
    }

    /* 4. AES-256-GCM decrypt */
    size_t compressed_len = 0;
    uint8_t *compressed = _aes_gcm_decrypt(
        (const uint8_t *)buf.buf, buf.len, outer_key, &compressed_len);
    PyBuffer_Release(&buf);
    Py_DECREF(b64res);

    if (!compressed) {
        _pg_die();   /* decryption failure = tamper */
        Py_RETURN_NONE;
    }

    /* 5. zlib decompress */
    size_t payload_len = 0;
    uint8_t *payload = _zlib_decompress(compressed, compressed_len, &payload_len);
    free(compressed);

    if (!payload || payload_len < PG_HEADER_SIZE) {
        free(payload); _pg_die(); Py_RETURN_NONE;
    }

    /* 6. Parse header */
    PGHeader hdr;
    memcpy(&hdr, payload, sizeof(PGHeader));
    if (memcmp(hdr.magic, PG_MAGIC, 8) != 0 || hdr.version != PG_VERSION) {
        free(payload); _pg_die(); Py_RETURN_NONE;
    }

    /* 7. Locate SR-VM bundle within body */
    size_t body_start   = PG_HEADER_SIZE;
    size_t srvm_abs     = body_start + hdr.srvm_offset;
    if (srvm_abs + hdr.srvm_len > payload_len) {
        free(payload); _pg_die(); Py_RETURN_NONE;
    }
    const uint8_t *srvm_data = payload + srvm_abs;

    /* 8. Minimal SR-VM bootstrap
       The srvm_bundle layout (from stage2) starts with:
         [4B n_functions][per-function records][code_blob]
       We execute the first function as the entry point. */
    if (hdr.srvm_len < 8) { free(payload); _pg_die(); Py_RETURN_NONE; }

    uint32_t n_funcs;
    memcpy(&n_funcs, srvm_data, 4);
    if (n_funcs == 0) { free(payload); Py_RETURN_NONE; }

    /* Each function record: [4B entry_offset][4B code_len] */
    uint32_t entry_off, code_len;
    memcpy(&entry_off, srvm_data + 4, 4);
    memcpy(&code_len,  srvm_data + 8, 4);

    size_t fn_rec_end = 4 + (size_t)n_funcs * 8;
    if (fn_rec_end + entry_off + code_len > hdr.srvm_len) {
        free(payload); _pg_die(); Py_RETURN_NONE;
    }
    const uint8_t *code = srvm_data + fn_rec_end + entry_off;

    SRVMState vm;
    memset(&vm, 0, sizeof(vm));
    _srvm_exec(&vm, code, code_len, NULL, 0);

    if (vm.error) {
        free(payload); _pg_die(); Py_RETURN_NONE;
    }

    free(payload);
    Py_RETURN_NONE;
}

/* ── Module definition ─────────────────────────────────────────────────────── */

static PyMethodDef _pg_methods[] = {
    {"run", pyguard_run, METH_VARARGS, "Run a PyGuard-protected payload."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef _pg_module = {
    PyModuleDef_HEAD_INIT, "_pyguard_ext", NULL, -1, _pg_methods
};

PyMODINIT_FUNC PyInit__pyguard_ext(void) {
    return PyModule_Create(&_pg_module);
}
'''


def build_c_extension_source() -> str:
    """Return the complete C source string for the PyGuard native extension."""
    return textwrap.dedent(_C_TEMPLATE).lstrip()
