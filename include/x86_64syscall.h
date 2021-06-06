

static inline long _syscall(long a, long b, long c, long d, long e, long f, long g)
{
    register long rax __asm__ ("rax") = a;
    register long rdi __asm__ ("rdi") = b;
    register long rsi __asm__ ("rsi") = c;
    register long rdx __asm__ ("rdx") = d;
    register long r10 __asm__ ("r10") = e;
    register long r8 __asm__ ("r8") = f;
    register long r9 __asm__ ("r9") = g;
    __asm__ __volatile__(
        "syscall"
        : "+r" (rax)
        : "r" (rdi), "r" (rsi), "r" (rdx), "r" (r10), "r" (r8), "r" (r9)
        : "cc", "rcx", "r11", "r12", "memory"
    );
    return rax;
}

#define STOREREG ("r14")

#define _mmap(addr, length, prot, flags, fd, pgoffset) _syscall(__NR_mmap, addr, length, prot, flags, fd, pgoffset);
#define _open(path, flags) _syscall(__NR_open, path, flags, 0, 0, 0, 0)
#define _close(fd) _syscall(__NR_close, fd, 0, 0, 0, 0, 0)
#define _read(fd, buf, nr) _syscall(__NR_read, fd, buf, nr, 0, 0, 0)
#define _write(fd, buf, nr) _syscall(__NR_write, fd, buf, nr, 0, 0, 0)
#define _kill(pid, sig) _syscall(__NR_kill, pid, sig, 0, 0, 0, 0)
#define _ptrace(request, pid, addr, data) _syscall(__NR_ptrace, request, pid, addr, data, 0, 0)
#define _getpid() _syscall(__NR_getpid, 0, 0, 0, 0, 0, 0)
#define _msync(addr, len, flags) _syscall(__NR_msync, addr, len, flags, 0, 0, 0)
