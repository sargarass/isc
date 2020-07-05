
set(archdetect_c_code "
/*
 * Architecture	      Predefined macros
	   aarch64	      __aarch64__
	   amd64	      __amd64__, __x86_64__
	   arm		      __arm__
	   armv6	      __arm__, __ARM_ARCH >= 6
	   armv7	      __arm__, __ARM_ARCH >= 7
	   i386		      __i386__
	   mips		      __mips__,	__MIPSEB__, __mips_o32
	   mipsel	      __mips__,	__mips_o32
	   mipselhf	      __mips__,	__mips_o32
	   mipshf	      __mips__,	__MIPSEB__, __mips_o32
	   mipsn32	      __mips__,	__MIPSEB__, __mips_n32
	   mips64	      __mips__,	__MIPSEB__, __mips_n64
	   mips64el	      __mips__,	__mips_n64
	   mips64elhf	      __mips__,	__mips_n64
	   mips64hf	      __mips__,	__MIPSEB__, __mips_n64
	   powerpc	      __powerpc__
	   powerpcspe	      __powerpc__, __SPE__
	   powerpc64	      __powerpc__, __powerpc64__
	   riscv64	      __riscv, __riscv_xlen == 64
	   riscv64sf	      __riscv, __riscv_xlen == 64
	   sparc64	      __sparc64__
 */
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(_M_ARM)
#   error cmake_ARCH TARGET_ARM
#elif defined(__i386) || defined(__i386__) || defined(_M_IX86)
#   error cmake_ARCH TARGET_I386
#elif defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(_M_X64)
#   if SIZE_MAX == 0xFFFFFFFF
#       error cmake_ARCH TARGET_X32
#   else
#       error cmake_ARCH TARGET_X86_64
#   endif
#elif defined(__ppc__) || defined(__ppc) || defined(__powerpc__) \\
      || defined(_ARCH_COM) || defined(_ARCH_PWR) || defined(_ARCH_PPC)  \\
      || defined(_M_MPPC) || defined(_M_PPC)
#   if defined(__ppc64__) || defined(__powerpc64__) || defined(__64BIT__)
#       error cmake_ARCH TARGET_PPC64
#   else
#       error cmake_ARCH TARGET_PPC
#   endif
#elif defined(__aarch64__)
#   error cmake_ARCH TARGET_AARCH64
#elif defined(__mips__) || defined(__MIPS__) || \\
      defined(__mips) || defined(__mips64) || defined(__MIPSEB__)
#   if defined(__mips_n32)
#       error cmake_ARCH TARGET_MIPSN32
#   elif defined(__mips_n64) || defined(__mips64)
#       error cmake_ARCH TARGET_MIPS64
#   elif defined(__mips_o32) || defined(__mips)
#       error cmake_ARCH TARGET_MIPS
#   endif
#elif defined(__riscv64) || (defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 64)
#   error cmake_ARCH TARGET_RISCV64
#endif

#error cmake_ARCH unknown
")

function(target_architecture output_var)
    file(WRITE "${CMAKE_BINARY_DIR}/arch.c" "${archdetect_c_code}")

    enable_language(C)

    # Detect the architecture in a rather creative way...
    # This compiles a small C program which is a series of ifdefs that selects a
    # particular #error preprocessor directive whose message string contains the
    # target architecture. The program will always fail to compile (both because
    # file is not a valid C program, and obviously because of the presence of the
    # #error preprocessor directives... but by exploiting the preprocessor in this
    # way, we can detect the correct target architecture even when cross-compiling,
    # since the program itself never needs to be run (only the compiler/preprocessor)
    try_run(
        run_result_unused
        compile_result_unused
        "${CMAKE_BINARY_DIR}"
        "${CMAKE_BINARY_DIR}/arch.c"
        COMPILE_OUTPUT_VARIABLE ARCH
    )

    # Parse the architecture name from the compiler output
    string(REGEX MATCH "cmake_ARCH ([a-zA-Z0-9_]+)" ARCH "${ARCH}")

    # Get rid of the value marker leaving just the architecture name
    string(REPLACE "cmake_ARCH " "" ARCH "${ARCH}")

    # If we are compiling with an unknown architecture this variable should
    # already be set to "unknown" but in the case that it's empty (i.e. due
    # to a typo in the code), then set it to unknown
    if (NOT ARCH)
        set(ARCH unknown)
    endif()

    set(${output_var} "${ARCH}" PARENT_SCOPE)
endfunction()
