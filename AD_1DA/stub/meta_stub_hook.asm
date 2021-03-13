BITS 64

section .text
    global _start

_start:

    lea r13, [rel $] ; rip

    mov rdi, [rsp+0x8]
    push r8
    mov r8, 0x3333333333333333 ; vaddr in the file
    sub r13, r8 ; r13 == base address
    pop r8
    push r13 ; base address

    ; Pushing all the registers in order to save the context

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

    mov rbp, rsp

    sub rsp, 144 ; stat_file 

    lea rsi, [rsp] ; stat_file
    
    mov r15, rsi ; &stat_file
    mov r12, rdi ; *pathname

    mov rax, 0x2
    mov rsi, 0x0 ; 0_RD
    mov rdx, 509
    syscall

    push rax ; fd

    mov rdi, rax ; fd
    mov rsi, r15 ; struct stat
    mov rax, 5 ; fstat
    syscall

    xor rdi, rdi
    mov rsi, qword [r15+48] ; stat_file.st_size
    mov rdx, 0x3
    mov r10, 0x2
    pop r8
    push r8
    mov r9, 0x0
    mov rax, 9
    syscall ; mmap(0x0, stat_file.st_size, 0x3, r10=0x2, r9=0x0, r8=fd);

    ; -----------

    push rdi
    push rsi
    push rcx
    push rax
    push r8
    push r9

    push rax

    ; -----------

    mov rdi, 0x6666666666666666 ; offset of the stub
    add rax, rdi ; addr du stub mapped

    mov rsi, rax

    mov rcx, 0x5555555555555555 ; len_stub => rcx

    xor r9, r9
    mov r9, 0xcccccccccccccc00
    add r9, 0xcc

__search_xor:
    lodsq
    sub rsi, 0x7 ; to step forward of only one byte
    xor rax, r9 ; 8 int3
    cmp rax, 0x0 ; if we found the pattern
    je __get_key
    loop __search_xor
    jmp __fail

__get_key:
    mov r8, [rsi+0x9] ; Ok check
    add rsi, 0x9
    mov r14, rsi ; location of the key / pointer to the key

__decrypt_text_file:
    mov rax, 0x1111111111111111 ; offset .text file
    pop rsi ; file mapped
    push rax ; offt text
    add rsi, rax ; rsi -> addr .text mapped file
    push rsi ; rsi -> addr .text mapped file

    mov rcx, 0x8888888888888888 ; len_text file
    push rcx ; len_text in file

    mov rdi, rsi ; addr text mapped

__loop_decrypt:
    lodsq
    xor rax, r8
    stosq
    loop __loop_decrypt

    pop rcx ; len_text in file
    pop rdi ; addr .text mapped
    pop r10 ; offset .text
    mov rsi, rdi ; addr .text mapped

    ; =-=-=- /dev/urandom =-=-=-=

    xor rax, rax
    push rax ; ?
    push rdi ; addr .text mapped
    push rsi ; addr .text mapped
    push rcx ; len_text in file

    sub rsp, 0x10
    mov dword [rsp], '/dev'
    mov dword [rsp+4], '/ura'
    mov dword [rsp+8], 'ndom'
    mov dword [rsp+12], 0x0000


    mov rax, 0x2
    lea rdi, [rsp] ; pointeur vers /dev/urandom
    mov rsi, 0x0 ; 0_RD
    mov rdx, 509 ; mode ?
    syscall ; open

    ; Now we gonna read this random number

    mov rdi, rax ; fd
    xor rax, rax ; 0
    sub rsp, 0x8
    lea rsi, [rsp]
    mov rdx, 0x8 ; we read 1 byte
    syscall ; sys read

    mov rdx, [rsi] ; get random number in rdx

    ; Now we gonna close the file descriptor

    mov rax, 3 ; sys_close
    syscall

    add rsp, 0x8
    add rsp, 0x10

    pop rcx ; len text in file
    pop rsi ; addr .text mapped
    pop rdi ; addr .text mapped
    pop rax ; ?

    ; =-=-=-=-=-=-=-=-=- /dev/urandom =-=-=-=-=-=-=-=-=-=

    push rcx ; len text in file
    xor rax, rax

__loop_encrypt:
    lodsq
    xor rax, rdx
    stosq
    loop __loop_encrypt

    pop rcx ; len .text

__edit_key:
    mov [r14], rdx ; set the key

    ; =-=-=-=-=-=-=

     ; garbage bytes between the first and the second pt_load

     ; =-=-=-=-=-=

    mov rsi, 0x7777777777777777 ; garbage offt
    mov rdi, 0x9999999999999999 ; last PT_LOAD offt in file

    push rsi ; end addr .text mapped
    push rdi ; end addr .text mapped
    push rcx ; len .text
    push rax ; shitty value

    sub rdi, rsi ; len where we gonna insert our "random" bytes
    mov rcx, rdi ; len where we gonna insert our "random" bytes

    mov rax, [rbp-184] ; A check (addr where the file is mapped)

    add rsi, rax ; addr -> code cave
    mov rdi, rsi

    sub rsp, 0x10
    mov dword [rsp], '/dev'
    mov dword [rsp+4], '/ura'
    mov dword [rsp+8], 'ndom'
    mov dword [rsp+12], 0x0000

__loop_random_bytes:
    push rsi ; addr code cave
    push rdi ; addr code cave
    push rcx ; length cave

    mov rax, 0x2
    lea rdi, [rsp+24] ; pointeur vers /dev/urandom
    mov rsi, 0x0 ; 0_RD
    mov rdx, 509
    syscall ; sys_open

    ; Now we gonna read this dandom number

    mov rdi, rax ; fd
    xor rax, rax ; 0x0
    sub rsp, 0x8 ; =-=-=-=-=-=
    lea rsi, [rsp] ; buf
    mov rdx, 0x1 ; read
    syscall ; sys read

    mov dl, byte [rsi] ; set byte

    ; Now we gonna close the file descriptor

    mov rax, 3
    syscall ; sys_close

    add rsp, 0x8 ; =-=-=-=-=-=

    pop rcx ; length cave
    pop rdi ; addr cave
    pop rsi ; addr cave

    lodsb
    xor al, dl
    stosb
    loop __loop_random_bytes

    add rsp, 0x10

    pop rax ; shitty value
    pop rcx ; len .text
    pop rdi ; end .text
    pop rsi ; end .text

    ; =-=-=-=-=-=

    mov rdi, qword [rbp+88] ; base address (begin pt load)
    mov r10, 0x1111111111111111 ; offset .text
    add r10, rdi ; addr at runtime of the .text à unpack

    ; Don't forget the mprotect

    mov rdi, r10
    push r10 ; addr virtual .text
    push r8 ; key

    push rcx

    mov rdx, 0x7 ; RWX
    mov rsi, 0x88888888888888cc ; special pattern for text length in bytes
    mov rax, 0xa; mprotect
    syscall

    pop rcx ; len .text

    pop r8
    pop rax

    mov rsi, rax
    mov rdi, rax

__decrypt_runtime:
    lodsq
    xor rax, r8
    stosq
    loop __decrypt_runtime

    pop r9
    pop r8
    pop rax
    pop rcx
    pop rsi
    pop rdi

; =================================

    mov r11, qword [r15+48]

    pop rsi ; fd

    push r11 ; len file
    push rax ; addr
    mov r14, rsi

    

    mov rdi, r12 ; pathname
    pop rsi ; addr
    pop rdx ; len
    push rdx
    push rsi
    
    ;call __create
    
    push rsi ; addr
    push rdx ; len

    push 'nasm'
    lea rdi, [rsp]
    mov rax, 0x2
    mov rsi, 0x42 ; 0_CREAT | O_RDWR
    mov rdx, 509
    syscall ; sys_open

    add rsp, 0x8 ; 'nasm'
    mov r9, rax ; fd
    mov rdi, rax ; fd

    mov rax, 0x1
    pop rdx
    pop rsi
    syscall ; sys_write

    mov rax, r9 ; fd final

    ; =====

    mov r13, rax ; second fd

    mov rdi, r14 ; fd
    pop rsi ; addr -> mmap
    pop rdx ; len_file
    
    ;call __close_unmap

    push rdi

    mov rdi, rsi
    mov rsi, rdx
    mov rax, 11
    syscall ; munmap(addr, len_file)

    pop rdi
    mov rax, 3
    syscall ; close(fd);

    ;================

    mov rax, 87
    mov rdi, r12
    syscall

    mov rax, 0x3 ; close(scnd_fd);
    mov rdi, r13
    syscall

    mov rax, 86
    push 'nasm'
    lea rdi, [rsp]
    mov rsi, r12
    syscall ; link tmp name to original name

    mov rax, 87
    lea rdi, [rsp]
    syscall ; delete old tmp file

    add rsp, 144

    mov rsp, rbp

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

    ; =-=-=-=-=-=-=-=-=-=-=-=

    ; Unpacking stub

    pop r13 ; base address
    mov rsi, 0x1010101010101010 ; pattern 0x11111111 for the begin of the .text
    add r13, rsi ; r13 begin of the .text to unpack

    ; == Pattern of int3 ==

    jmp $+10 ; 8 * 0xcc + something

__int3:
    int3
    int3
    int3
    int3
    int3
    int3
    int3
    int3

__ehe:
    mov r8, 0x4444444444444444 ; key_text
    
    ; In asm : 
    ;int3                         ; +0 = cc 
    ;int3                         ; +1 = cc 
    ;int3                         ; +2 = cc 
    ;int3                         ; +3 = cc 
    ;int3                         ; +4 = cc 
    ;int3                         ; +5 = cc 
    ;int3                         ; +6 = cc 
    ;int3                         ; +7 = cc 
    ;mov r8b, 0x0000000000000044  ; +8 = 41 b0 44 44 is teh key

    ; == End of pattern ==

    ; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

    mov rax, r13
    jmp rax

__fail:
    mov rax, 60
    mov rdi, 0xff
    syscall