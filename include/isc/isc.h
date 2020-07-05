//
// Copyright (c) 2020 Anton Bornev, Bastion LTD
//
// https://github.com/sargarass/isc
//
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
#pragma once
#include <thread>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <poll.h>
#include <mqueue.h>

namespace isc {
    using syscall_arg_t = long;
    // signal for syscalls interruption, DO NOT BLOCK IT. Should be real-time signal
    const int interaption_signal = SIGRTMAX;

    // if the thread handles *interaption_signal* while it is not in isc's syscall,
    //    nothing will happen.
    // if a signal occurs while the thread is in isc's syscall and stop_token wasnt touched,
    //    nothing will happend (syscall will just restart).
    // if *interaption_signal* occurs while the thread is in isc's syscall and the stop_token is triggered
    //    then syscall will be interrupted and -1 will be returned and errno will be set to ECANCELED.

    // on error returns the error code and doesnt change errno.
    syscall_arg_t syscall_err_in_ret(std::stop_token const &token, syscall_arg_t syscall, syscall_arg_t arg1 = 0, syscall_arg_t arg2 = 0, syscall_arg_t arg3 = 0, syscall_arg_t arg4 = 0, syscall_arg_t arg5 = 0, syscall_arg_t arg6 = 0) noexcept;
    
    // on error returns -1 and sets errno to the error code.                      
    syscall_arg_t syscall(std::stop_token const &token, syscall_arg_t syscall, syscall_arg_t arg1 = 0, syscall_arg_t arg2 = 0, syscall_arg_t arg3 = 0, syscall_arg_t arg4 = 0, syscall_arg_t arg5 = 0, syscall_arg_t arg6 = 0) noexcept;
    int accept(std::stop_token const &token, int fd, struct sockaddr *addr, socklen_t * len) noexcept;
    int accept4(std::stop_token const &token, int fd, struct sockaddr *addr, socklen_t * len, int flags) noexcept;
    int clock_nanosleep(std::stop_token const &token, clockid_t clk, int flags, const struct timespec *req, struct timespec *rem) noexcept;
    int close(std::stop_token const &token, int fd) noexcept;
    int connect(std::stop_token const &token, int fd, const struct sockaddr *addr, socklen_t len) noexcept;
    int creat(std::stop_token const &token, const char *filename, mode_t mode = 0) noexcept;
    int fcntl(std::stop_token const &token, int fd, int cmd) noexcept;
    int fcntl(std::stop_token const &token, int fd, int cmd, long arg) noexcept;
    int fcntl(std::stop_token const &token, int fd, int cmd, struct flock *lock) noexcept;
    int fdatasync(std::stop_token const &token, int fd) noexcept;
    int lockf(std::stop_token const &token, int fd, int op, off_t size) noexcept;
    ssize_t mq_receive(std::stop_token const &token, mqd_t mqd, char *msg, size_t len, unsigned *prio) noexcept;
    int mq_send(std::stop_token const &token, mqd_t mqd, const char *msg, size_t len, unsigned prio) noexcept;
    ssize_t mq_timedreceive(std::stop_token const &token, mqd_t mqd, char *msg, size_t len, unsigned *prio, const struct timespec *at) noexcept;
    int mq_timedsend(std::stop_token const &token, mqd_t mqd, const char *msg, size_t len, unsigned prio, const struct timespec *at) noexcept;
    ssize_t msgrcv(std::stop_token const &token, int q, void *m, size_t len, long type, int flag) noexcept;
    int msgsnd(std::stop_token const &token, int q, const void *m, size_t len, int flag) noexcept;
    int msync(std::stop_token const &token, void *start, size_t len, int flags) noexcept;
    int nanosleep(std::stop_token const &token, const struct timespec *req, struct timespec *rem) noexcept;
    int open(std::stop_token const &token, const char *pathname, int flags, mode_t mode) noexcept;
    int openat(std::stop_token const &token, int fd, const char *filename, int flags, mode_t mode = 0) noexcept;
    int pause(std::stop_token const &token) noexcept;
    int poll(std::stop_token const &token, struct pollfd *fds, nfds_t n, int timeout) noexcept;
    ssize_t pread(std::stop_token const &token, int fd, void *buf, size_t count, off_t offset) noexcept;
    ssize_t pwrite(std::stop_token const &token, int fd, const void *buf, size_t size, off_t ofs) noexcept;
    ssize_t read(std::stop_token const &token, int fd, void *buf, size_t nbyte) noexcept;
    ssize_t readv(std::stop_token const &token, int fd, const struct iovec *vector, int count) noexcept;
    ssize_t recv(std::stop_token const &token, int fd, void *buf, size_t len, int flags) noexcept;
    ssize_t recvfrom(std::stop_token const &token, int fd, void *buf, size_t len, int flags, struct sockaddr *addr, socklen_t *alen) noexcept;
    ssize_t recvmsg(std::stop_token const &token, int fd, struct msghdr *msg, int flags) noexcept;
    int select(std::stop_token const &token, int n, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *tv) noexcept;
    ssize_t send(std::stop_token const &token, int fd, const void *buf, size_t len, int flags) noexcept;
    ssize_t sendmsg(std::stop_token const &token, int fd, const struct msghdr *msg, int flags) noexcept;
    ssize_t sendto(std::stop_token const &token, int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t alen) noexcept;
    int sigpause(std::stop_token const &token, int sig) noexcept;
    int sigsuspend(std::stop_token const &token, const sigset_t *mask) noexcept;
    int sigtimedwait(std::stop_token const &token, const sigset_t *mask, siginfo_t *info, const struct timespec *timeout) noexcept;
    int sigwait(std::stop_token const &token, const sigset_t *set, int *sig) noexcept;
    int sigwaitinfo(std::stop_token const &token, const sigset_t *mask, siginfo_t *info) noexcept;
    unsigned sleep(std::stop_token const &token, unsigned seconds) noexcept;
    void sync(std::stop_token const &token) noexcept;
    int tcdrain(std::stop_token const &token, int fd) noexcept;
    int usleep(std::stop_token const &token, unsigned useconds) noexcept;
    pid_t wait(std::stop_token const &token, int *wstatus) noexcept;
    pid_t wait3(std::stop_token const &token, int *wstatus, int options, struct rusage *rusage) noexcept;
    pid_t wait4(std::stop_token const &token, pid_t pid, int *wstatus, int options, struct rusage *rusage) noexcept;
    int waitid(std::stop_token const &token, idtype_t idtype, id_t id, siginfo_t *infop, int options) noexcept;
    pid_t waitpid(std::stop_token const &token, pid_t pid, int *wstatus, int options) noexcept;
    ssize_t write(std::stop_token const &token, int fd, const void *buf, size_t count) noexcept;
    ssize_t writev(std::stop_token const &token, int fd, const struct iovec *vector, int count) noexcept;
}
