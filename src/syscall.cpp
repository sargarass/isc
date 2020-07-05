//
// Copyright (c) 2020 Anton Bornev, Bastion LTD
//
// https://github.com/sargarass/isc
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
// Based on Musl's code which is MIT Licensed.
#include <cassert>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <string.h>
#include <isc/detail/arch.h>
#include <isc/isc.h>

using isc::interaption_signal;
using syscall_arg_t = isc::syscall_arg_t;

extern "C" {
    __attribute__((__visibility__("hidden")))
    extern const char __cp_begin[1], __cp_end[1], __cp_cancel[1];

    __attribute__((__visibility__("hidden")))
    long __syscall_cp_asm(volatile void *, syscall_arg_t,
                          syscall_arg_t, syscall_arg_t, syscall_arg_t,
                          syscall_arg_t, syscall_arg_t, syscall_arg_t);

    __attribute__((__visibility__("hidden")))
    long __cancel() {
        return -ECANCELED;
    }
}

static thread_local std::atomic_long token_canceled = 0;

static void signal_handler_for_cancellation(int mysignal, siginfo_t *si, void* context) {
    assert(mysignal == interaption_signal);
    auto syscall_begin_label = reinterpret_cast<uintptr_t>(__cp_begin);
    auto syscall_end_label = reinterpret_cast<uintptr_t>(__cp_end);
    auto cancel_label = reinterpret_cast<uintptr_t>(__cp_cancel);

    ucontext_t *ucontext = (ucontext_t*)context;
    uintptr_t &pc = reinterpret_cast<uintptr_t &>(ucontext->uc_mcontext.ISC_PC_REG);
    if (pc >= syscall_begin_label &&
        pc < syscall_end_label &&
        token_canceled.load(std::memory_order_acquire)) {
        pc = cancel_label;
        return;
    }
}

syscall_arg_t isc::syscall_err_in_ret(std::stop_token const &token,
                                      syscall_arg_t syscall,
                                      syscall_arg_t arg1,
                                      syscall_arg_t arg2,
                                      syscall_arg_t arg3,
                                      syscall_arg_t arg4,
                                      syscall_arg_t arg5,
                                      syscall_arg_t arg6) noexcept {
    token_canceled.store(0, std::memory_order_release);

    static bool init = false;
    if (!init) {
        struct sigaction sig_action;
        memset(&sig_action, 0, sizeof(sig_action));
        sig_action.sa_flags = SA_SIGINFO | SA_RESTART;
        sig_action.sa_handler = (decltype(sig_action.sa_handler))((void *)signal_handler_for_cancellation);
        sigemptyset (&sig_action.sa_mask);
        sigaction (interaption_signal, &sig_action, nullptr);
    }

    std::stop_callback cb(token, [token_canceled_p = &token_canceled, thread_id = pthread_self()](){
        token_canceled_p->store(1, std::memory_order_release);
        pthread_kill(thread_id, interaption_signal);
    });

    auto result = __syscall_cp_asm(&token_canceled, syscall, arg1, arg2, arg3, arg4, arg5, arg6);
    if (result == -EINTR && token_canceled) {
        return -ECANCELED;
    }
    return result;
}

syscall_arg_t isc::syscall(std::stop_token const &token,
                    syscall_arg_t syscall,
                    syscall_arg_t arg1,
                    syscall_arg_t arg2,
                    syscall_arg_t arg3,
                    syscall_arg_t arg4,
                    syscall_arg_t arg5,
                    syscall_arg_t arg6) noexcept {
    auto result = syscall_err_in_ret(token, syscall, arg1, arg2, arg3, arg4, arg5, arg6);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}
