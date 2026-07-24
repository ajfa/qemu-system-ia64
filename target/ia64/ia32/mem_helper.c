/* Reuse QEMU's x86 memory helpers for IA-32 mode. */

#include "helper-compat.h"
#define X86_CPU_ARCH_ENV(env) ((CPUIA64State *)(env))
#include "target/i386/tcg/mem_helper.c"
