.global _start

.text
target_path:
	.ascii "target.out\0"

_start:
	push %rbp
	mov %rsp, %rbp
	sub $128, %rbp

	#mmap
	mov $9, %rax
	mov $0, %rdi
	mov $1024, %rsi
	mov $3, %rdx
	mov $0x22, %r10
	mov $-1, %r8
	mov $0, %r9
	syscall
	mov %rax, (%rbp)

	#open
	mov $2, %rax
	mov $target_path, %rdi
	mov $02, %rsi
	mov $0, %rdx
	syscall
	mov %rax, 8(%rbp)

	#read header
	mov $0, %rax
	mov 8(%rbp), %rdi
	mov (%rbp), %rsi
	mov $128, %rdx
	syscall

	#dump to stdout
	mov $1, %rax
	mov $1, %rdi
	syscall

	#exit
	mov $60, %rax
	syscall
