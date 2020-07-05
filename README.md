# Intruduction

The idea of syscall canceleration isn't new. Musl and GLibc implement [posix pthread_cancel](https://man7.org/linux/man-pages/man3/pthread_cancel.3.html) which allows to terminate the target thread while also interrupts a branch of syscalls. For termination target thread throws specific exception (like *abi::__force unwind* for Glibc). In synchronous case it occurs whenever target thread reaches certain functions (cancellation points). [Most of them are syscalls wrappers](https://man7.org/linux/man-pages/man7/pthreads.7.html). 
While this approach was valid in C, in C++ many of those functions are used in the standard library in noexcept functions or destructors. Moreover syscalls like close usually used in a client code in RAII idiom. Whenever exception thrown from destructor, program termination happens which means pthread_cancel isn't suitable for C++ (small example [here](https://skaark.wordpress.com/2010/08/26/pthread_cancel-considered-harmful/)).

# Jthreads and ISC

C++20 provide us with jthreads. Each jthread is connected to a special atomic flag: stop_token. Whenever stop_token is triggered, it is a user task to process canceleration. Some of std functions may accept stop_token and be interrabled when it was triggerd. This library add support to interrupt the subset of blocking linux syscalls. For each system call it adds one additional parameter - stop_token. Whenever canceleration is requested through stop_token the syscall is interrupted, -1 is returned and errno is setted in ECANCELED. Cancellation does not occur on completed system calls, so resources are not leaked.

Small example:
```C++
#include <iostream>
#include <isc/isc.h>
#include <unistd.h>

void test(std::stop_token token) {
    char buff[1024];
    isc::read(token, 0, buff, 1024);
    if (!token.stop_requested()) {
        std::cout << buff << std::endl;
    } else {
        /* interrupt handling */
        std::cout << std::system_category().message(errno) << std::endl;
    }
}

int main()
{
    std::jthread t(test);
    sleep(1);
    t.request_stop();
    t.join();
    return 0;
}
```
If something will arrived to stdin thread t will read it and terminate. If nothing have arrived in 1s task will be interrupted. And thread will output text representation of errno variable.

# Supported syscalls:
```C++
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
```

# Supported architectures:
While execution wasn't tested on all of them, ISC supports many architectures thanks to Musl asm code: x86_64, i386, x32, powerpc, powerpc64, aarch64, arm, mips, mips64, mipsn32, riscv64.

# How to use it

First of all you need compiler that supports C++20. After you got it, just add the library as a subdirectory to your project and link your cmake target with isc::isc target. Now you can include <isl/isl.h> and start using the library. Also check that your aplication doesn't block *interaption_signal* (SIGRTMAX by default).

# It sounds great, but how does it work?

Let's say *target thread* is a jthread which is performing some task. At some point of time it performs isc's syscall:
1. It checks if a signal handler has been installed. If not, sets it up.
2. Associates std::stop_callback with a stop_token passed to isc's syscall. The callback will store 1 to thread_local variable *token_canceled* and send *interaption_signal* to the this thread if token will be triggered.
3. Checks if interuption was requested, if it was perform canceleration (return -1 and errno=ECANCELED) otherwise makes the syscall.

4. While the target thread is in the syscall, canceleration can be requested through the token. Whenever it happends, stop_callback occurs and target thread will handle the *interaption_signal* in the special handler. In this handler it will check if: 
thread_local variable *token_canceled* is setted to 1 and PC counter is inside isl's syscall labels (checkout *a clever hack* [here](https://lwn.net/Articles/683118/)). If someone else sent us a signal the target thread will just restart syscall. If signal arrived after syscall was finished, nothing will happend (PC counter out of syscall labels). If target thread is preforming syscall and canceleration is requested then target thread's PC counter will be changed to start of __cancel funtion that just returns -ECANCELED as the syscall result.

5. Special case check result of the syscall is -EINTR && *token_canceled* is 1 => return -1 and errno=ECANCELED.
6. Return result of the system call (uses errno if it needs to).
