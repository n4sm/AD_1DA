BITS 64

section .text
    global _start

_start:
    mov rax, 0x1
    mov rdi, 0x1
    push 'nasm'
    lea rsi, [rsp]
    mov rdx, 4
    syscall
    mov rax, 0x1
    mov rdi, 0x1
    push 0xa
    lea rsi, [rsp]
    mov rdx, 0x1
    syscall
    mov rax, 60
    mov rdi, 0x0
    syscall
