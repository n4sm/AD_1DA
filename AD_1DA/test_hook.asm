BITS 64

section .text
    global _start

_start:

    lea r12, [rel $]

    push r8
    mov r8, 0x33333333 ; mon offset dans le fic
    sub r12, r8 ; r12 == base address
    pop r8

    ; On push tous les regs pour save de context

    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11

    ; code to inject here

    mov rax, 0x1
    mov rdi, 0x1
    push 'nasm'
    lea rsi, [rsp]
    mov rdx, 4
    syscall
    add rsp, 0x8 ; Pas oublier de pas perturber la stack
    mov rax, 0x1
    mov rdi, 0x1
    push 0xa
    lea rsi, [rsp]
    mov rdx, 0x1
    syscall
    add rsp, 0x8 ; Pas oublier de pas perturber la stack

    ; code to inject here


    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax

    mov rax, 0x11111111 ; pattern 0x11111111 for the begin of the .text
    add rax, r12
    jmp rax











