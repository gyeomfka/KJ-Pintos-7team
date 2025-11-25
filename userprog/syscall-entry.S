#include "threads/loader.h"

.text
.globl syscall_entry
.type syscall_entry, @function
syscall_entry:
	movq %rbx, temp1(%rip)
	movq %r12, temp2(%rip)     /* callee saved registers */
	movq %rsp, %rbx            /* Store userland rsp    */
	movabs $tss, %r12
	movq (%r12), %r12
	movq 4(%r12), %rsp         /* Read ring0 rsp from the tss */
	/* Now we are in the kernel stack */
	push $(SEL_UDSEG)      /* if->ss */
	push %rbx              /* if->rsp */
	push %r11              /* if->eflags */
	push $(SEL_UCSEG)      /* if->cs */
	push %rcx              /* if->rip */
	subq $16, %rsp         /* skip error_code, vec_no */
	push $(SEL_UDSEG)      /* if->ds */
	push $(SEL_UDSEG)      /* if->es */
	push %rax              // syscall vector number
	movq temp1(%rip), %rbx
	push %rbx
	pushq $0
	push %rdx              // syscall 인자 3
	push %rbp
	push %rdi              // syscall 인자 1
	push %rsi              // syscall 인자 2
	push %r8               // syscall 인자 5
	push %r9               // syscall 인자 6
	push %r10              // syscall 인자 4
	pushq $0 /* skip r11 */
	movq temp2(%rip), %r12
	push %r12
	push %r13
	push %r14
	push %r15
	movq %rsp, %rdi        // syscall_handler가 사용할 interrupt_frame 인자를 셋업(h/w interrupt가 다시 살아남)

check_intr:
	btsq $9, %r11          /* Check whether we recover the interrupt */
	jnb no_sti
	sti                    /* restore interrupt */
no_sti:
	movabs $syscall_handler, %r12   // syscall 핸들러 실행
	call *%r12
	popq %r15   // syscall 핸들러 실행이 완료되면 stack에 넣어둔 registers 값을 복구한다.
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rsi
	popq %rdi
	popq %rbp
	popq %rdx
	popq %rcx
	popq %rbx
	popq %rax
	addq $32, %rsp
	popq %rcx              /* if->rip */
	addq $8, %rsp
	popq %r11              /* if->eflags */
	popq %rsp              /* if->rsp */
	sysretq  // %MSR에 따라 %CS, %SS의 CPL을 user mode로 복구 및 %rip, %rflags 복구

.section .data
.globl temp1
temp1:
.quad	0
.globl temp2
temp2:
.quad	0
