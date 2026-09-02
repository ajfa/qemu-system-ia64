/* IA-64 TCG helper ABI adapters for firmware-assist bridges. */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "arch/arch.h"

uint32_t helper_firmware_debug_enter(CPUIA64State *env, uint64_t address)
{
    return ia64_firmware_debug_enter(env, address);
}

uint32_t helper_firmware_debug_save(CPUIA64State *env)
{
    return ia64_firmware_debug_save(env);
}

uint32_t helper_firmware_debug_restore(CPUIA64State *env)
{
    return ia64_firmware_debug_restore(env);
}

void helper_aix_watch(CPUIA64State *env, uint64_t ip)
{
    ia64_aix_watch(env, ip);
}

uint32_t helper_sal_runtime_enter(CPUIA64State *env)
{
    return ia64_sal_runtime_enter(env);
}

uint32_t helper_sal_runtime_exit(CPUIA64State *env)
{
    return ia64_sal_runtime_exit(env);
}
