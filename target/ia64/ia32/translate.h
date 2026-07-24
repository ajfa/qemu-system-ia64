/* QEMU x86 TCG adapter for IA-64 IA-32 application execution mode. */

#ifndef TARGET_IA64_IA32_TRANSLATE_H
#define TARGET_IA64_IA32_TRANSLATE_H

void ia64_ia32_translate_init(void);
void ia64_ia32_translate_code(CPUState *cs, TranslationBlock *tb,
                              int *max_insns, vaddr pc, void *host_pc);

#endif /* TARGET_IA64_IA32_TRANSLATE_H */
