global proxy_call_returns
global proxy_call_fakestack
global proxy_call_fakestack_size
global spoofcall_stub

section .bss
    proxy_call_returns resq 32
    proxy_call_fakestack resq 1
    proxy_call_fakestack_size resq 1

section .text
spoofcall_stub:
    push 0
    push r9
    push r8
    push rdx
    push rcx

    mov rax, rdx
    mov rcx, rsp
    add rcx, 0x50
    mov rdx, rcx

    cmp qword [rsp], 0x46C4660
    jz end_args_calc

    mov rax, r8
    cmp qword [rsp + 8], 0x46C4660
    jz end_args_calc

    mov rax, r9
    cmp r8, 0x46C4660
    jz end_args_calc

    mov rax, [rcx]
    cmp r9, 0x46C4660
    jz end_args_calc

check_for_args_end:
    mov rax, [rcx + 8]
    cmp qword [rcx], 0x46C4660
    jz end_args_calc
    add rcx, 8
    jmp check_for_args_end

end_args_calc:
    sub rcx, rdx
    lea r8, [rel cleanup_call]
    push r8

    mov r10, rcx
    mov rcx, [rel proxy_call_fakestack_size]
    cmp rcx, 0
    jz skip_fakecallstack

    lea r8, [rcx * 8]
    sub rsp, r8

    mov r8, rsi
    mov r9, rdi

    mov rsi, [rel proxy_call_fakestack]
    mov rdi, rsp
    rep movsq

    mov rsi, r8
    mov rdi, r9

skip_fakecallstack:
    mov rcx, r10

    mov r8, rcx
    and r8, 15
    mov r8, rcx
    jnz stack_aligned
    push 0
    add r8, 8
stack_aligned:

push_value:
    cmp rcx, 0
    jz do_call
    push qword [rdx + rcx - 8]
    sub rcx, 8
    jmp push_value

do_call:
    add r8, 0x20
    push 0
    push 0
    push 0
    push 0

    lea r9, [rel proxy_call_returns]
    mov r9, [r9 + r8]
    push r9

    mov r9, [rdx - 0x38]
    mov r8, [rdx - 0x40]
    mov rcx, [rdx - 0x50]
    mov rdx, [rdx - 0x48]
    jmp rax

cleanup_call:
    add rsp, 0x28
    ret
