ia64_ss = ss.source_set()
ia64_ss.add(files(
  'decoder.c',
  'cpu.c',
  'fpreg.c',
  'op_helper.c',
  'exec-access.c',
  'ia32/translate.c',
  'ia32/access.c',
  'ia32/cc_helper.c',
  'ia32/int_helper.c',
  'ia32/fpu_helper.c',
  'ia32/mem_helper.c',
  'ia32/misc_helper.c',
  'ia32/seg_helper.c',
  'ia32/state.c',
  'ia32/excp_helper.c',
  'ia32/system_helper.c',
  'ia32/transition_helper.c',
))
target_arch += {'ia64': ia64_ss}
