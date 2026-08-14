/* IA-64 TCG helper ABI adapters for interrupt and timer state. */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "arch/arch.h"

uint64_t helper_itc_read(CPUIA64State *env)
{
    return ia64_interrupt_itc_read(env);
}
