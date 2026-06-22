.global arena_call_sysv_spoof
.text
arena_call_sysv_spoof:
    # Save callee-saved registers
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    # Save target parameters to registers we won't overwrite immediately
    # rdi = fn
    # rsi = args
    # rdx = count
    # rcx = gadget_jmp
    # r8  = gadget_ret
    movq %rdi, %r12       # r12 = fn
    movq %rsi, %r13       # r13 = args
    movq %rdx, %r14       # r14 = count
    movq %rcx, %r15       # r15 = gadget_jmp
    # r8 (gadget_ret) will go into r10 before the call

    # Set up stack arguments for target function if count > 6
    # System V passes first 6 args in RDI, RSI, RDX, RCX, R8, R9.
    # Args 6, 7, ... (0-indexed) go on the stack in reverse order.
    cmpq $6, %r14
    jle no_stack_args

    # Calculate S (number of stack args: count - 6)
    movq %r14, %rax
    subq $6, %rax        # rax = S
    
    # Align stack to 16 bytes boundary
    # If S is odd, we push a dummy value (8 bytes) to maintain alignment
    testq $1, %rax
    jz stack_args_even
    pushq $0             # Dummy push for alignment
stack_args_even:
    movq %r14, %rbx      # rbx = count
loop_stack_args:
    decq %rbx            # rbx = count - 1, ..., 6
    movq (%r13,%rbx,8), %rax
    pushq %rax
    cmpq $6, %rbx
    jg loop_stack_args

no_stack_args:
    # Push cleanup label as return address target for gadget_ret
    leaq cleanup_label(%rip), %rax
    pushq %rax           # This is where gadget_ret will return to!
    
    pushq %r15           # This is gadget_jmp. The target function's ret will jump here!

    # Set up r10 to point to gadget_ret
    movq %r8, %r10

    # Load the first 6 arguments into registers:
    # RDI = args[0]
    # RSI = args[1]
    # RDX = args[2]
    # RCX = args[3]
    # R8  = args[4]
    # R9  = args[5]
    cmpq $0, %r14
    je do_call
    movq 0(%r13), %rdi
    cmpq $1, %r14
    je do_call
    movq 8(%r13), %rsi
    cmpq $2, %r14
    je do_call
    movq 16(%r13), %rdx
    cmpq $3, %r14
    je do_call
    movq 24(%r13), %rcx
    cmpq $4, %r14
    je do_call
    movq 32(%r13), %r8
    cmpq $5, %r14
    je do_call
    movq 40(%r13), %r9

do_call:
    # Jump to target function
    jmpq *%r12

cleanup_label:
    # Restore RSP to clean up any stack arguments we pushed
    movq %rbp, %rsp
    subq $40, %rsp       # Restore to position after callee-saved pushes (5 * 8 = 40)
    
    # Restore callee-saved registers
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    retq
