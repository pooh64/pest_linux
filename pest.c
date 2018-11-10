#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

const char STR_EXIT[] = "\x48\xC7\xC0\x3C\x00\x00\x00\x0F\x05";

int main()
{
	int fd = open("a.out", O_RDWR);
	if (fd == -1) {
		perror("open");
		return 0;
	}
	Elf64_Ehdr header = { };
	if (read(fd, &header, sizeof(header)) == -1) {
		perror("read");
		return 0;
	}
	uint64_t addr = header.e_entry;
	printf("%" PRIu64 "\n", header.e_entry);
	
	if (lseek(fd, addr, 0) == -1) {
		perror("lseek");
		return 0;
	}
	
	if (write(fd, STR_EXIT, sizeof(STR_EXIT)) == -1) {
		perror("write");
		return 0;
	}
	
	return 0;
}
