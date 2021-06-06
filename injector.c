#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/uio.h>
#include <linux/ptrace.h>
#include <elf.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <malloc.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <error.h>


#define FAILED_TO_TRACE() \
    printf("[+] Failed to trace %d\n", pid); \
    exit(1);


extern unsigned char _binary_raw_shellcode_bin_start;
extern unsigned char _binary_raw_shellcode_bin_end;
extern long _binary_raw_shellcode_bin_size;

void* tracee_pc_saved_data;


struct user_regs_struct saved_uregs;
struct user_regs_struct uregs;


/**
 * xtou64
 * Take a hex string and convert it to a 64bit number (max 16 hex digits).
 * The string must only contain digits and valid hex characters.
 */
uint64_t xtou64(const char *str)
{
    uint64_t res = 0;
    char c;

    while ((c = *str++)) {
        char v = (c & 0xF) + (c >> 6) | ((c >> 3) & 0x8);
        res = (res << 4) | (uint64_t) v;
    }

    return res;
}

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

/* scan /proc/<pid>/maps for a rwx page with the given sentinel value.
 * // format to parse is: 7f6444c4c000-7f6444c4e000 rwxp 00000000 00:00 0
 *
 */

void * find_marked_rwx_region_in_tracee(int pid, size_t sentinel){
    void* ret = NULL;
    FILE * mapsfilp = NULL;
    int memfd = -1;
    char mapspathbuf[128];
    memset(mapspathbuf, 0, sizeof(mapspathbuf));
    snprintf(mapspathbuf, sizeof(mapspathbuf), "/proc/%d/maps", pid);

    char mempathbuf[128];
    memset(mempathbuf, 0, sizeof(mempathbuf));
    snprintf(mempathbuf, sizeof(mempathbuf), "/proc/%d/mem", pid);

    if ((mapsfilp = fopen(mapspathbuf, "rt")) == NULL){
        perror("fopen maps");
        return NULL;
    }

    if ((memfd = open(mempathbuf, O_RDONLY)) == -1){
        perror("open mem");
        return NULL;
    }

    char * line = NULL;
    size_t n = 0;
    int found = 0;
    char* token = NULL;
    size_t seekaddr = 0;
    struct {
        size_t value;
    } sentinel_candidate = { 0 };
    while ((getline(&line, &n, mapsfilp)) != -1){
        if (strstr(line, " rwxp ") != NULL){
            //printf("rwx line found\n%s", line);
            token = strsep(&line, "-");
            if (line != NULL){
                // delimeter found
                seekaddr = xtou64(token);

                if (lseek(memfd, seekaddr, SEEK_SET) == -1){
                    perror("lseek seekaddr");
                    goto nextline;
                }

                if (read(memfd, &sentinel_candidate, sizeof(sentinel_candidate)) == -1){
                    perror("read sentinel candidate");
                    goto nextline;
                }

                if (sentinel_candidate.value == sentinel){
                    ret = (void*)seekaddr;
                }
            }
nextline:
            // set line back to its original-ish value so that it can be cleaned up by free
            line = token;
            if (ret != NULL){
                break;
            }
        }

        free(line);
        line = NULL;
        n = 0;
    }


    // getline allocates a buffer even if it fails
    if (line != NULL){
        free(line);
    }
    fclose(mapsfilp);
    close(memfd);

    return ret;
}



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
    if (lseek(fd, saved_uregs.rip, SEEK_SET) == -1){
        perror("lseek");
        return -1;
    }
    if (read(fd, tracee_pc_saved_data, &_binary_raw_shellcode_bin_size) == -1){
        perror("read saved process code");
        return -1;
    }
    if (lseek(fd, saved_uregs.rip, SEEK_SET) == -1){
        perror("lseek to instruction pointer");
        return -1;
    }
    if (write(fd, &_binary_raw_shellcode_bin_start, &_binary_raw_shellcode_bin_size) == -1){
        perror("write initial shellcode");
        return -1;
    }
    close(fd);

    memcpy(&uregs, &saved_uregs, sizeof(uregs));
    //print_x86_64_registers(&saved_uregs);
    //DumpHex(tracee_pc_saved_data, &_binary_raw_shellcode_bin_size);

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


int restore_register_state(int pid){

    struct iovec iov = {.iov_len = sizeof(saved_uregs),
                        .iov_base = &saved_uregs};
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

int restore_process_state(int pid){
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
        printf("returning early, null start\n");
        return -1;
    }

    sprintf(buf, "/proc/%d/mem", pid);
    if ((memfd = open(buf, O_RDWR)) == -1){
        perror("open proc mem");
        return -1;
    }
    if (lseek(memfd, region_start, SEEK_SET) == -1){
        perror("lseek on proc mem");
        return -1;
    }
    while (total_written < binary_size){
        if((num_read = read(shellcode_fd, working_memory, sizeof(working_memory))) == -1){
            perror("read shellcode binary");
            return -1;
        } else if (num_read == 0){
            break;
        }
        if ((num_written = write(memfd, working_memory, num_read)) == -1){
            perror("write to proc mem");
            printf("errno %d\n", errno);
            return -1;
        }
        printf("[+] wrote %d to %p\n", num_written, region_start + total_written);
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

    printf("[+] Executing initial shellcode\n");
    // Execute initial shellcode
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1){
        perror("ptrace");
    }

    if (waitpid(pid, &wstatus, WUNTRACED) == -1){
        perror("waitpid");
        FAILED_TO_TRACE();
    }

    // inital shellcode has finished running
    printf("[+] Initial shellcode finished execution\n");
    if (WIFSTOPPED(wstatus)) {
        // WSTOPSIG
        printf("[+] Stopped target process again\n");
    } else {
        printf("Incorrect wstatus\n");
        FAILED_TO_TRACE();
    }

    void* rwx_region = find_marked_rwx_region_in_tracee(pid, 0xcccccccccccccccc);
    printf("[+] rwx region found %p\n", rwx_region);
    struct iovec iov = {.iov_len = sizeof(uregs),
                        .iov_base = &uregs};
    /*
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }
    */
    //print_x86_64_registers(&uregs);


    // adjust rip to point to the controlled memory
    /*
    uregs.rip = rwx_region;

    // set regs to fix pc
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1){
        perror("ptrace");
        exit(1);
    }
    */
    // recover initial shellcode region
    //restore_process_state(pid);

    // write binary to injectee and jump to address
    write_binary(pid, shellcode_fd, size, rwx_region);


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
    //while (1) {}



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
