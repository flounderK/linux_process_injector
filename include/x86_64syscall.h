

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

