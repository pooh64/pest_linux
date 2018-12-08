.global _start

.text
target_path:			#testing
	.ascii "target.out\0"

_start:
	call __infector_core
	
	#exit
	mov $60, %rax
	syscall


__infector_core:

	push %rbp
	mov %rsp, %rbp
	sub $128, %rbp

	mov $9, %rax		#mmap 1024 bytes
	mov $0, %rdi
	mov $1024, %rsi
	mov $3, %rdx
	mov $0x22, %r10
	mov $-1, %r8
	mov $0, %r9
	syscall
	mov %rax, (%rbp)

	mov $2, %rax		#open target
	mov $target_path, %rdi
	mov $02, %rsi
	mov $0, %rdx
	syscall
	mov %rax, 8(%rbp)

	mov $0, %rax		#read some data
	mov 8(%rbp), %rdi
	mov (%rbp), %rsi
	mov $128, %rdx
	syscall

	mov $1, %rax		#dump to stdout
	mov $1, %rdi
	syscall

	add $128, %rbp
	mov %rbp, %rsp
	pop %rbp
	ret
