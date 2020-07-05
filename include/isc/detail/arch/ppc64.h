#pragma once
// the kernel calls the ip "nip", it's the first saved value after the 32
// GPRs.
#define ISC_PC_REG gp_regs[32]

#define ISC_SYSCALL_LL_E(x) (x)
#define ISC_SYSCALL_LL_O(x) (x)
