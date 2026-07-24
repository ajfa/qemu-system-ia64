/* Build-time adapter for QEMU's reusable x86 TCG helper sources. */

#ifndef TARGET_IA64_IA32_HELPER_COMPAT_H
#define TARGET_IA64_IA32_HELPER_COMPAT_H

#include "qemu/osdep.h"
#include "cpu.h"
#include "accel/tcg/getpc.h"

/* Declare upstream helper entry points using the embedded x86 view. */
#include "exec/helper-head.h.inc"
#undef dh_ctype_env
#define dh_ctype_env CPUX86State *
#define HELPER_H "target/i386/helper.h"
#include "exec/helper-proto.h.inc"
#undef HELPER_H

/* Suppress the target-wide IA-64 declarations in imported source files. */
#define HELPER_PROTO_H

/* target/ia64/ia32/compat.h deliberately keeps these target-local. */
#define CC_DST  (env->cc_dst)
#define CC_SRC  (env->cc_src)
#define CC_SRC2 (env->cc_src2)
#define CC_OP   (env->cc_op)

#endif /* TARGET_IA64_IA32_HELPER_COMPAT_H */
