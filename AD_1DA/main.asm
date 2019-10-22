BITS 64

section .text
    global _start

_start:
    push   rbp
	mov    rbp,rsp
	sub    rsp,0x10
    mov    DWORD [rbp+0xc], 0x22
	movsd  rax,DWORD [rbp+0xc]
	mov    DWORD [rbp-0x4],rax
    mov    DWORD [rbp+0x8], 0xe
	mov    rax,DWORD [rbp+0x8]
	mov    DWORD [rbp-0x8],rax
	jmp    __cmp_

__cmp2_:
	add    DWORD [rbp-0x4],0x1
	add    DWORD [rbp-0x8],0xd1
	

__cmp_:
    cmp    DWORD [rbp-0x8],0x9087
	jle    __cmp2_
    mov    rax,DWORD [rbp-0x4]
	leave  
	ret    
