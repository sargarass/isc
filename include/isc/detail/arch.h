#pragma once
#if defined(TARGET_ARM)
#   include "arch/arm.h"
#elif defined (TARGET_AARCH64)
#   include "arch/aarch64.h"
#elif defined(TARGET_X86_64)
#   include "arch/x86_64.h"
#elif defined(TARGET_X32)
#   include "arch/x32.h"
#elif defined(TARGET_I386)
#   include "arch/i386.h"
#elif defined(TARGET_PPC64)
#   include "arch/ppc64.h"
#elif defined(TARGET_PPC)
#   include "arch/ppc.h"
#elif defined(TARGET_MIPS)
# include "arch/mips.h"
#elif defined(TARGET_MIPS64)
# include "arch/mips64.h"
#elif defined(TARGET_MIPSN32)
#   include "arch/mipsn32.h"
#elif defined(TARGET_RISCV64)
#   include "arch/riscv64.h"
#else
#   error "isc: Unsupported arch"
#endif

#define ISC_SYSCALL_LL_PRW(x) ISC_SYSCALL_LL_O(x)
