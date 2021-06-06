#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include "x86_64syscall.h"


void * _memcpy(void* dest, void * src, size_t len){
    char *d = dest;
    const char *s = src;
    while (len--){
        *d++ = *s++;
    }
    return dest;
}


/* This serves as initial shellcode to create an environment that
 *
 */
void _start(size_t size){

    _write(1, "Hello world\n", 12);
    void * addr = _mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (addr == NULL){
        //_write(1, "NULL Address, error\n", 20);
        goto exit;
    }
    int pid = _getpid();

    //if (_ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1){
    //    _write(1, "bad ptrace, error\n", 18);
    //}
    void (*shellcode_region)() = addr;
    void **new_memory_region_start = addr;
    // opcode for hardware breakpoint
    *new_memory_region_start = 0xcccccccccccccccc;
    //alert tracing process
    _kill(pid, SIGINT);

    _msync(addr, size, MS_SYNC);

    shellcode_region();

exit:
    return;
}




