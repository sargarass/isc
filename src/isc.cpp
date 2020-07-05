//
// Copyright (c) 2020 Anton Bornev, Bastion LTD
//
// https://github.com/sargarass/isc
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
// Based on Musl's code which is MIT Licensed.
#include <sys/ioctl.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <cstdio>
#include <cstdarg>
#include <fcntl.h>
#include <spawn.h>
#include <sys/ipc.h>
#include <mqueue.h>
#include <unistd.h>
#include <sys/socket.h>

#include <isc/isc.h>
#include <isc/detail/arch.h>

extern "C" long syscall(long number, ...);
#define IS32BIT(x) !(((x)+0x80000000ULL)>>32U)
#define CLAMP(x) (int)(IS32BIT(x) ? (x) : 0x7fffffffU+((0ULL+(x))>>63U))

namespace isc {
    template<typename Syscall, typename ...Args>
    auto syscall_wrapper(std::stop_token const &token, Syscall syscall_n, Args &&... args) noexcept {
        return syscall(token, syscall_arg_t(syscall_n), uintptr_t(std::forward<Args>(args))...);
    }

    template<typename Syscall, typename ...Args>
    auto syscall_err_in_ret_wrapper(std::stop_token const &token, Syscall syscall_n, Args &&... args) noexcept {
        return syscall_err_in_ret(token, syscall_arg_t(syscall_n), uintptr_t(std::forward<Args>(args))...);
    }

    template<typename I>
    I syscall_ret(I r) {
        if (r < 0) {
            errno = -r;
            return -1;
        }
        return r;
    }

    template<typename Syscall, typename ...Args>
    auto syscall_wrapper(Syscall syscall_n, Args &&... args) noexcept {
        return ::syscall(long(syscall_n), long(std::forward<Args>(args))...);
    }

    ssize_t write(std::stop_token const &token, int fd, const void *buf, size_t count) noexcept {
        return syscall_wrapper(token, SYS_write, fd, buf, count);
    }
    
    ssize_t read(std::stop_token const &token, int fd, void *buf, size_t nbyte) noexcept {
        return syscall_wrapper(token, SYS_read, fd, buf, nbyte);
    }

    ssize_t pread(std::stop_token const &token, int fd, void *buf, size_t count, off_t offset) noexcept {
        return syscall_wrapper(token, SYS_pread64, fd, buf, count, ISC_SYSCALL_LL_PRW(offset));
    }

    ssize_t pwrite(std::stop_token const &token, int fd, const void *buf, size_t size, off_t ofs) noexcept {
        return syscall_wrapper(token, SYS_pwrite64, fd, buf, size, ISC_SYSCALL_LL_PRW(ofs));
    }

    int open(std::stop_token const &token, const char *pathname, int flags, mode_t mode) noexcept {
#       ifdef SYS_open
            int fd = syscall_wrapper(token, SYS_open, pathname, uint32_t(flags) | uint32_t(O_LARGEFILE), mode);
#       else
            int fd = syscall_wrapper(token, SYS_openat, AT_FDCWD, pathname, uint32_t(flags) | uint32_t(O_LARGEFILE), mode);
#       endif
        // Musl does it. Shouldn't kernel set O_CLOEXEC if we passed right flags to the call above?
        if (fd >= 0 && (uint32_t(flags) & uint32_t(O_CLOEXEC))) {
            syscall_wrapper(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC);
        }
        return fd;
    }

    int creat(std::stop_token const &token, const char *filename, mode_t mode) noexcept {
        return open(token, filename, O_CREAT|O_WRONLY|O_TRUNC, mode);
    }

    int close(std::stop_token const &token, int fd) noexcept {
        //fixme: Musl also does fd = __aio_close(fd)...
        int r = syscall_wrapper(token, SYS_close, fd);
        if (r == -1 && errno == EINTR) {
            errno = 0;
            return 0;
        }
        return r;
    }

    int nanosleep(std::stop_token const &token, const struct timespec *req, struct timespec *rem) noexcept {
        return syscall_wrapper(token, SYS_nanosleep, req, rem);
    }

    unsigned sleep(std::stop_token const &token, unsigned seconds) noexcept {
        struct timespec tv = { .tv_sec = decltype(tv.tv_sec)(seconds), .tv_nsec = 0 };
        if (nanosleep(token, &tv, &tv))
            return tv.tv_sec;
        return 0;
    }

    int usleep(std::stop_token const &token, unsigned useconds) noexcept {
        struct timespec tv = {
                .tv_sec = decltype(tv.tv_sec)((useconds / 1000000)),
                .tv_nsec = decltype(tv.tv_nsec)((useconds % 1000000)*1000)
        };
        return nanosleep(token, &tv, &tv);
    }

    int fcntl(std::stop_token const &token, int fd, int cmd) noexcept {
        if (cmd == F_SETLKW) {
            return syscall_wrapper(token, fd, cmd, 0);
        }
        return ::fcntl(fd, cmd);
    }

    int fcntl(std::stop_token const &token, int fd, int cmd, long arg) noexcept {
        if (cmd == F_SETLKW) {
            return syscall_wrapper(token, fd, cmd, arg);
        }
        return ::fcntl(fd, cmd, arg);
    }

    int fcntl(std::stop_token const &token, int fd, int cmd, struct flock *lock) noexcept {
        return fcntl(token, fd, cmd, (long)lock);
    }

    ssize_t readv(std::stop_token const &token, int fd, const struct iovec *vector, int count) noexcept {
        return syscall_wrapper(token, SYS_readv, fd, vector, count);
    }

    ssize_t writev(std::stop_token const &token, int fd, const struct iovec *vector, int count) noexcept {
        return syscall_wrapper(token, SYS_writev, fd, vector, count);
    }

    pid_t wait4(std::stop_token const &token, pid_t pid, int *wstatus, int options, struct rusage *rusage) noexcept {
        return syscall_wrapper(token, SYS_wait4, pid, wstatus, options, rusage);
    }

    pid_t wait3(std::stop_token const &token, int *wstatus, int options, struct rusage *rusage) noexcept {
        return wait4(token, -1, wstatus, options, rusage);
    }

    pid_t waitpid(std::stop_token const &token, pid_t pid, int *wstatus, int options) noexcept {
        return syscall_wrapper(token, SYS_wait4, pid, wstatus, options, 0);
    }

    int tcdrain(std::stop_token const &token, int fd) noexcept {
        return syscall_wrapper(token, SYS_ioctl, fd, TCSBRK, 1);
    }

    pid_t wait(std::stop_token const &token, int *wstatus) noexcept {
        return waitpid(token, (pid_t)-1, wstatus, 0);
    }

    int waitid(std::stop_token const &token, idtype_t idtype, id_t id, siginfo_t *infop, int options) noexcept {
        return syscall_wrapper(token, SYS_waitid, idtype, id, infop, options, 0);
    }

    void sync(std::stop_token const &token) noexcept {
        syscall_wrapper(token, SYS_sync);
    }

    int sigtimedwait(std::stop_token const &token, const sigset_t *mask, siginfo_t *info, const struct timespec *timeout) noexcept {
        int ret;
        do {
            ret = syscall_wrapper(token, SYS_rt_sigtimedwait, mask, info, timeout, _NSIG/8); // both glibc & musl uses _NSIG/8
        }
        while (ret < 0 && errno == EINTR);
        return ret;
    }

    int sigwaitinfo(std::stop_token const &token, const sigset_t *mask, siginfo_t *info) noexcept {
        return sigtimedwait(token, mask, info, nullptr);
    }

    int sigwait(std::stop_token const &token, const sigset_t *set, int *sig) noexcept {
        siginfo_t si;
        if (sigtimedwait(set, &si, nullptr) < 0)
            return -1;
        *sig = si.si_signo;
        return 0;
    }

    int sigsuspend(std::stop_token const &token, const sigset_t *mask) noexcept {
        return syscall_wrapper(token, SYS_rt_sigsuspend, mask, _NSIG/8);
    }

    int sigpause(std::stop_token const &token, int sig) noexcept {
        sigset_t mask;
        sigprocmask(0, nullptr, &mask);
        sigdelset(&mask, sig);
        return sigsuspend(token, &mask);
    }

    int select(std::stop_token const &token, int n, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *tv) noexcept {
        time_t s = tv ? tv->tv_sec : 0;
        suseconds_t us = tv ? tv->tv_usec : 0;
        [[maybe_unused]] long ns;
        const time_t max_time = (1ULL << (8 * sizeof(time_t)-1)) - 1;

        if (s < 0 || us < 0) {
            errno = -EINVAL;
            return -1;
        }

        if (us / 1000000 > max_time - s) {
            s = max_time;
            us = 999999;
            ns = 999999999;
        } else {
            s += us / 1000000;
            us %= 1000000;
            ns = us * 1000;
        }

#   ifdef SYS_pselect6_time64
        int r = -ENOSYS;
        if (SYS_pselect6 == SYS_pselect6_time64 || !IS32BIT(s)) {
            long long tmp[] = {s, ns};
            syscall_arg_t last_val[] = { 0, _NSIG/8 };
            r = syscall_err_in_ret_wrapper(token, SYS_pselect6, n, rfds, wfds, efds, tv ? tmp : nullptr, last_val);
        }
        if (SYS_pselect6 == SYS_pselect6_time64 || r != -ENOSYS)
            return syscall_ret(r);
#   endif
        long tmp[]{static_cast<long>(s), static_cast<long>(us)};
#   ifdef SYS_select
        return syscall_wrapper(token, SYS_select, n, rfds, wfds, efds,tv ? tmp : nullptr);
#   else
        syscall_arg_t last_val[] = { 0, _NSIG/8 };
        return syscall_wrapper(token, SYS_pselect6, n, rfds, wfds, efds, tv ? tmp : nullptr, last_val);
#   endif
    }

    int poll(std::stop_token const &token, struct pollfd *fds, nfds_t n, int timeout) noexcept {
#   ifdef SYS_poll
        return syscall_wrapper(token, SYS_poll, fds, n, timeout);
#   else
        struct timespec tmp = { timeout/1000, timeout % 1000 * 1000000 };
        return syscall_wrapper(token, SYS_ppoll, fds, n, timeout>=0 ? &tmp : nullptr, 0, _NSIG/8);
#   endif
    }

    int pause(std::stop_token const &token) noexcept {
#   ifdef SYS_pause
        return syscall_wrapper(token, SYS_pause);
#   else
        return syscall_wrapper(token, SYS_ppoll, 0, 0, 0, 0);
#   endif
    }

    int msync(std::stop_token const &token, void *start, size_t len, int flags) noexcept {
        return syscall_wrapper(token, SYS_msync, start, len, flags);
    }

    int msgsnd(std::stop_token const &token, int q, const void *m, size_t len, int flag) noexcept {
#   ifndef SYS_ipc
        return syscall_wrapper(token, SYS_msgsnd, q, m, len, flag);
#   else
#       ifndef IPCOP_msgsnd
#           define IPCOP_msgsnd 11
#       endif
        return syscall_wrapper(SYS_ipc, IPCOP_msgsnd, q, len, flag, m);
#   endif
    }

    ssize_t msgrcv(std::stop_token const &token, int q, void *m, size_t len, long type, int flag) noexcept {
#   ifndef SYS_ipc
            return syscall_wrapper(token, SYS_msgrcv, q, m, len, type, flag);
#   else
#       ifndef IPCOP_msgrcv
#           define IPCOP_msgrcv    12
#       endif
        long tmp[] = { (long)m, type };
        return syscall_wrapper(token, SYS_ipc, IPCOP_msgrcv, q, len, flag, tmp);
#   endif
    }

    int mq_timedsend(std::stop_token const &token, mqd_t mqd, const char *msg, size_t len, unsigned prio, const struct timespec *at) noexcept {
#   ifdef SYS_mq_timedsend_time64
        time_t s = at ? at->tv_sec : 0;
        long ns = at ? at->tv_nsec : 0;
        long r = -ENOSYS;
        if (SYS_mq_timedsend == SYS_mq_timedsend_time64 || !IS32BIT(s)) {
            long long tmp[] = {at->tv_sec, at->tv_nsec};
            r = syscall_err_in_ret_wrapper(token, SYS_mq_timedsend_time64, mqd, msg, len, prio, at ? tmp : 0);
        }
        if (SYS_mq_timedsend == SYS_mq_timedsend_time64 || r != -ENOSYS)
            return syscall_ret(r);
        long tmp[] = {CLAMP(s), ns};
        return syscall_wrapper(token, SYS_mq_timedsend, mqd, msg, len, prio, at ? tmp : nullptr);
#   else
        return syscall_wrapper(token, SYS_mq_timedsend, mqd, msg, len, prio, at);
#   endif
    }

    ssize_t mq_timedreceive(std::stop_token const &token, mqd_t mqd, char *msg, size_t len, unsigned *prio, const struct timespec *at) noexcept {
#   ifdef SYS_mq_timedreceive_time64
        time_t s = at ? at->tv_sec : 0;
        long ns = at ? at->tv_nsec : 0;
        long r = -ENOSYS;
        if (SYS_mq_timedreceive == SYS_mq_timedreceive_time64 || !IS32BIT(s)) {
            long long tmp[] = {at->tv_sec, at->tv_nsec};
            r = syscall_err_in_ret_wrapper(token, SYS_mq_timedreceive_time64, mqd, msg, len, prio, at ? tmp : 0);
        }
        if (SYS_mq_timedreceive == SYS_mq_timedreceive_time64 || r != -ENOSYS)
            return syscall_ret(r);
        long tmp[] = {CLAMP(s), ns};
        return syscall_wrapper(token, SYS_mq_timedreceive, mqd, msg, len, prio, at ? tmp : nullptr);
#   else
        return syscall_wrapper(token, SYS_mq_timedreceive, mqd, msg, len, prio, at);
#   endif
    }

    int mq_send(std::stop_token const &token, mqd_t mqd, const char *msg, size_t len, unsigned prio) noexcept {
        return mq_timedsend(token, mqd, msg, len, prio, nullptr);
    }

    ssize_t mq_receive(std::stop_token const &token, mqd_t mqd, char *msg, size_t len, unsigned *prio) noexcept {
        return mq_timedreceive(token, mqd, msg, len, prio, nullptr);
    }

    int lockf(std::stop_token const &token, int fd, int op, off_t size) noexcept {
        struct flock l = {};
        l.l_type = F_WRLCK;
        l.l_whence = SEEK_CUR;
        l.l_len = size;

        switch (op) {
            case F_TEST:
                l.l_type = F_RDLCK;
                if (fcntl(token, fd, F_GETLK, &l) < 0)
                    return -1;
                if (l.l_type == F_UNLCK || l.l_pid == ::getpid())
                    return 0;
                errno = EACCES;
                return -1;
            case F_ULOCK:
                l.l_type = F_UNLCK;
                [[fallthrough]];
            case F_TLOCK:
                return fcntl(token, fd, F_SETLK, &l);
            case F_LOCK:
                return fcntl(token, fd, F_SETLKW, &l);
            default:;
        }
        errno = EINVAL;
        return -1;
    }

    int accept4(std::stop_token const &token, int fd, struct sockaddr *addr, socklen_t * len, int flags) noexcept {
        return syscall_wrapper(token, SYS_accept4, fd, addr, len);
    }

    int accept(std::stop_token const &token, int fd, struct sockaddr *addr, socklen_t * len) noexcept {
        return accept4(token, fd, addr, len, 0);
    }

#ifndef SYS_clock_nanosleep
    #define SYS_clock_nanosleep SYS_clock_nanosleep_time64
#endif    
#ifndef SYS_clock_nanosleep
    #define SYS_clock_nanosleep SYS_clock_nanosleep_time32
#endif
    
int clock_nanosleep(std::stop_token const &token, clockid_t clk, int flags, const struct timespec *req, struct timespec *rem) noexcept {
        if (clk == CLOCK_THREAD_CPUTIME_ID) return EINVAL;
#ifdef SYS_clock_nanosleep_time64
        time_t s = req->tv_sec;
	long ns = req->tv_nsec;
	int r = -ENOSYS;
	if (SYS_clock_nanosleep == SYS_clock_nanosleep_time64 || !IS32BIT(s)) {
	    long long tmp[] = {s, ns};
        r = syscall_err_in_ret_wrapper(token, SYS_clock_nanosleep_time64, clk, flags, tmp, rem);
    }
	if (SYS_clock_nanosleep == SYS_clock_nanosleep_time64 || r!=-ENOSYS)
		return -r;
	long long extra = s - CLAMP(s);
	long ts32[2] = { CLAMP(s), ns };
	if (clk == CLOCK_REALTIME && !flags)
		r = syscall_err_in_ret_wrapper(token, SYS_nanosleep, &ts32, &ts32);
	else
		r = syscall_err_in_ret_wrapper(token, SYS_clock_nanosleep, clk, flags, &ts32, &ts32);
	if (r==-EINTR && rem && !(uint32_t(flags) & uint32_t(TIMER_ABSTIME))) {
		rem->tv_sec = ts32[0] + extra;
		rem->tv_nsec = ts32[1];
	}
	return -r;
#else
        if (clk == CLOCK_REALTIME && !flags)
            return -syscall_err_in_ret_wrapper(token, SYS_nanosleep, req, rem);
        return -syscall_err_in_ret_wrapper(token, SYS_clock_nanosleep, clk, flags, req, rem);
#endif
    }

    int connect(std::stop_token const &token, int fd, const struct sockaddr *addr, socklen_t len) noexcept {
        return syscall_wrapper(token, SYS_connect, fd, addr, len);
    }

    int fdatasync(std::stop_token const &token, int fd) noexcept {
        return syscall_wrapper(token, SYS_fdatasync, fd);
    }

    int openat(std::stop_token const &token, int fd, const char *filename, int flags, mode_t mode) noexcept {
        return syscall_wrapper(token, SYS_openat, fd, filename, uint32_t(flags) | uint32_t(O_LARGEFILE), mode);
    }

    ssize_t recvfrom(std::stop_token const &token, int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *alen) noexcept {
        return syscall_wrapper(token, SYS_recvfrom, fd, buf, len, flags, addr, alen);
    }

    ssize_t recv(std::stop_token const &token, int fd, void *buf, size_t len, int flags) noexcept {
        return recvfrom(token, fd, buf, len, flags, nullptr, nullptr);
    }

    ssize_t recvmsg(std::stop_token const &token, int fd, struct msghdr *msg, int flags) noexcept {
        return syscall_wrapper(token, SYS_recvmsg, fd, msg, flags);
    }

    ssize_t sendto(std::stop_token const &token, int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t alen) noexcept {
        return syscall_wrapper(token, SYS_sendto, fd, buf, len, flags, addr, alen);
    }

    ssize_t send(std::stop_token const &token, int fd, const void *buf, size_t len, int flags) noexcept {
        return sendto(token, fd, buf, len, flags, nullptr, 0);
    }

    ssize_t sendmsg(std::stop_token const &token, int fd, const struct msghdr *msg, int flags) noexcept {
        return syscall_wrapper(token, SYS_sendmsg, fd, msg, flags);
    }
}
