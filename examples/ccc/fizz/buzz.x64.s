	.file	"buzz.c"
	.text
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"fizz buzz!"
.LC1:
	.string	"fizz..."
.LC2:
	.string	"buzz?"
.LC3:
	.string	"%d\n"
	.section	.text.startup,"ax",@progbits
	.globl	main
	.type	main, @function
main:
.LFB13:
	.cfi_startproc
	endbr64
	pushq	%r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	movl	$1, %r12d
	pushq	%rbx
	.cfi_def_cfa_offset 24
	.cfi_offset 3, -24
	movl	$15, %ebx
	pushq	%rax
	.cfi_def_cfa_offset 32
.L6:
	movl	%r12d, %eax
	leaq	.LC0(%rip), %rdi
	cltd
	idivl	%ebx
	testl	%edx, %edx
	je	.L8
	movl	%r12d, %eax
	movl	$3, %ecx
	cltd
	idivl	%ecx
	testl	%edx, %edx
	jne	.L4
	leaq	.LC1(%rip), %rdi
.L8:
	call	puts@PLT
	jmp	.L3
.L4:
	movl	%r12d, %eax
	movl	$5, %ecx
	leaq	.LC2(%rip), %rdi
	cltd
	idivl	%ecx
	testl	%edx, %edx
	je	.L8
	movl	%r12d, %edx
	leaq	.LC3(%rip), %rsi
	movl	$1, %edi
	xorl	%eax, %eax
	call	__printf_chk@PLT
.L3:
	incl	%r12d
	jmp	.L6
	.cfi_endproc
.LFE13:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	 1f - 0f
	.long	 4f - 1f
	.long	 5
0:
	.string	 "GNU"
1:
	.align 8
	.long	 0xc0000002
	.long	 3f - 2f
2:
	.long	 0x3
3:
	.align 8
4:
