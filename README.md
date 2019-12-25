[![forthebadge](https://forthebadge.com/images/badges/made-with-c.svg)](https://forthebadge.com)

# AD_1DA

AD_1DA is a modern tool made in order to obfuscate your elf binaries.

## Installation



```bash
git clone https://github.com/n4sm/AD_1DA
cd AD_1DA
chmod +x build.sh
./build.sh
```

Next, you have severals binaries : 

**main   :    which is the main binary ( type ./main -h )**

**test_  :    which is a target C binary (you can look at /test_folder/test.c)**

**test   :    which is a nasm binary that will be injected in the target file (only the .text)**

## Utilisation
Help :
```bash
$ ./main -h
AD_1DA is a modern tool made in order to obfuscate your elf binaries
Help : 
                ./main -h : Show this help
                ./main <target_binary> -o <stub to inject>: Basic obfuscation (in work)
                ./main <target_binary> -m <stub_to inject>: Create a new binary (<target_binary>.p4cked), which will be metamorphic and polymorphic
                ./main <target_binary> -o <stub_to_inject> -pie: Inject stub_to_inject and patching it as a stub injected in a position independant executable binary
```

Usage : 
```bash
$ ./main
Usage : ./main <target_file> <option> <stub_to_inject>
Help : ./main -h
```

Inject code :

```bash
$ ./main test_ -o test_hook
Raw executables bytes in the stub : 
        4c8d25f9ffffff415041b8333333334d29c44158504889e04883c0853515255575641504151415241534989c3b82000498b7b8f5415b415a415941585e5f5d5a595b58b8111111114c1e0ffe0
Disassembling the stub : 
        [lea]      r12, qword ptr [rip - 7]
        [push]      r8
        [mov]      r8d, 0x33333333
        [sub]      r12, r8
        [pop]      r8
        [push]      rax
        [mov]      rax, rsp
        [add]      rax, 8
        [push]      rbx
        [push]      rcx
        [push]      rdx
        [push]      rbp
        [push]      rdi
        [push]      rsi
        [push]      r8
        [push]      r9
        [push]      r10
        [push]      r11
        [mov]      r11, rax
        [mov]      eax, 2
        [mov]      rdi, qword ptr [r11 + 8]
        [syscall]      _
        [pop]      r11
        [pop]      r10
        [pop]      r9
        [pop]      r8
        [pop]      rsi
        [pop]      rdi
        [pop]      rbp
        [pop]      rdx
        [pop]      rcx
        [pop]      rbx
        [pop]      rax
        [mov]      eax, 0x11111111
        [add]      rax, r12
        [jmp]      rax
Second pt_load is found at 0xdb8
The binary has the pie !
Entry point rewritten : 0x201030
[*] Generating a new test_.p4cked executable file
Bytes injected at 0x201030: 
       4c8d25f9ffffff415041b830102004d29c44158504889e04883c0853515255575641504151415241534989c3b82000498b7b8f5415b415a415941585e5f5d5a595b58b8305004c1e0ffe0
Length of the stub : 0x51
```
It will inject test_hook in test_.

**Warning : the stub that you want to inject must be a file developped in assembly file which must be executable**


Metamorphism : 

```

$ ./main test_ -m meta_stub_hook -pie
Raw executables bytes in the stub : 
        4c8d2df9ffffff488b7c248415049b833333333333333334d29c5415841555053515255575641504151415241534889e54881ec90000488d34244989f74989fcb82000be0000bafd100f5504889c74c89feb85000f54831ff498b7730ba300041ba20004158415041b90000b89000f557565150415041515048bf6666666666666666481f84889c648b9555555555555555549b90cccccccccccccc4981c1cc00048ad4883ee74c31c84883f8074ce2efb83c0004831fff5448a4694883c694989f648b811111111111111115e50481c65648b98888888888888888514889f7ac4430c0aae2f9595f415a4889fef31481c251ac30d0aae2fa5941881648be7777777777777777488b7d58491fa4152415051ba7000b8a000f5594158584889c64889c7ac4430c0aae2f94159415858595e5f4d8b5f305e4153504989f64c89e75e5a52565652686e61736d488d3c24b82000be42000bafd100f54883c484989c14889c7b810005a5ef54c89c84989c54c89f75e5a574889f74889d6b8b000f55fb83000f5b8570004c89e7f5b830004c89eff5b856000686e61736d488d3c244c89e6f5b857000488d3c24f54881c4900004889ec415b415a415941585e5f5d5a595b58415d48be1111111111111111491f5eb8cccccccccccccccc49b844444444444444444c89e8ffe0
Disassembling the stub : 
        [lea]      r13, qword ptr [rip - 7]
        [mov]      rdi, qword ptr [rsp + 8]
        [push]      r8
        [movabs]      r8, 0x3333333333333333
        [sub]      r13, r8
        [pop]      r8
        [push]      r13
        [push]      rax
        [push]      rbx
        [push]      rcx
        [push]      rdx
        [push]      rbp
        [push]      rdi
        [push]      rsi
        [push]      r8
        [push]      r9
        [push]      r10
        [push]      r11
        [mov]      rbp, rsp
        [sub]      rsp, 0x90
        [lea]      rsi, qword ptr [rsp]
        [mov]      r15, rsi
        [mov]      r12, rdi
        [mov]      eax, 2
        [mov]      esi, 0
        [mov]      edx, 0x1fd
        [syscall]      _
        [push]      rax
        [mov]      rdi, rax
        [mov]      rsi, r15
        [mov]      eax, 5
        [syscall]      _
        [xor]      rdi, rdi
        [mov]      rsi, qword ptr [r15 + 0x30]
        [mov]      edx, 3
        [mov]      r10d, 2
        [pop]      r8
        [push]      r8
        [mov]      r9d, 0
        [mov]      eax, 9
        [syscall]      _
        [push]      rdi
        [push]      rsi
        [push]      rcx
        [push]      rax
        [push]      r8
        [push]      r9
        [push]      rax
        [movabs]      rdi, 0x6666666666666666
        [add]      rax, rdi
        [mov]      rsi, rax
        [movabs]      rcx, 0x5555555555555555
        [movabs]      r9, -0x3333333333333400
        [add]      r9, 0xcc
        [lodsq]      rax, qword ptr [rsi]
        [sub]      rsi, 7
        [xor]      rax, r9
        [cmp]      rax, 0
        [je]      0xd3
        [loop]      0xb8
        [mov]      eax, 0x3c
        [xor]      rdi, rdi
        [syscall]      _
        [mov]      r8b, byte ptr [rsi + 9]
        [add]      rsi, 9
        [mov]      r14, rsi
        [movabs]      rax, 0x1111111111111111
        [pop]      rsi
        [push]      rax
        [add]      rsi, rax
        [push]      rsi
        [movabs]      rcx, -0x7777777777777778
        [push]      rcx
        [mov]      rdi, rsi
        [lodsb]      al, byte ptr [rsi]
        [xor]      al, r8b
        [stosb]      byte ptr [rdi], al
        [loop]      0xfc
        [pop]      rcx
        [pop]      rdi
        [pop]      r10
        [mov]      rsi, rdi
        [rdtsc]      _
        [add]      rdx, rax
        [push]      rcx
        [lodsb]      al, byte ptr [rsi]
        [xor]      al, dl
        [stosb]      byte ptr [rdi], al
        [loop]      0x110
        [pop]      rcx
        [mov]      byte ptr [r14], dl
        [movabs]      rsi, 0x7777777777777777
        [mov]      rdi, qword ptr [rbp + 0x58]
        [add]      r10, rdi
        [push]      r10
        [push]      r8
        [push]      rcx
        [mov]      edx, 7
        [mov]      eax, 0xa
        [syscall]      _
        [pop]      rcx
        [pop]      r8
        [pop]      rax
        [mov]      rsi, rax
        [mov]      rdi, rax
        [lodsb]      al, byte ptr [rsi]
        [xor]      al, r8b
        [stosb]      byte ptr [rdi], al
        [loop]      0x146
        [pop]      r9
        [pop]      r8
        [pop]      rax
        [pop]      rcx
        [pop]      rsi
        [pop]      rdi
        [mov]      r11, qword ptr [r15 + 0x30]
        [pop]      rsi
        [push]      r11
        [push]      rax
        [mov]      r14, rsi
        [mov]      rdi, r12
        [pop]      rsi
        [pop]      rdx
        [push]      rdx
        [push]      rsi
        [push]      rsi
        [push]      rdx
        [push]      0x6d73616e
        [lea]      rdi, qword ptr [rsp]
        [mov]      eax, 2
        [mov]      esi, 0x42
        [mov]      edx, 0x1fd
        [syscall]      _
        [add]      rsp, 8
        [mov]      r9, rax
        [mov]      rdi, rax
        [mov]      eax, 1
        [pop]      rdx
        [pop]      rsi
        [syscall]      _
        [mov]      rax, r9
        [mov]      r13, rax
        [mov]      rdi, r14
        [pop]      rsi
        [pop]      rdx
        [push]      rdi
        [mov]      rdi, rsi
        [mov]      rsi, rdx
        [mov]      eax, 0xb
        [syscall]      _
        [pop]      rdi
        [mov]      eax, 3
        [syscall]      _
        [mov]      eax, 0x57
        [mov]      rdi, r12
        [syscall]      _
        [mov]      eax, 3
        [mov]      rdi, r13
        [syscall]      _
        [mov]      eax, 0x56
        [push]      0x6d73616e
        [lea]      rdi, qword ptr [rsp]
        [mov]      rsi, r12
        [syscall]      _
        [mov]      eax, 0x57
        [lea]      rdi, qword ptr [rsp]
        [syscall]      _
        [add]      rsp, 0x90
        [mov]      rsp, rbp
        [pop]      r11
        [pop]      r10
        [pop]      r9
        [pop]      r8
        [pop]      rsi
        [pop]      rdi
        [pop]      rbp
        [pop]      rdx
        [pop]      rcx
        [pop]      rbx
        [pop]      rax
        [pop]      r13
        [movabs]      rsi, 0x1111111111111111
        [add]      r13, rsi
        [jmp]      0x21b
        [int3]      _
        [int3]      _
        [int3]      _
        [int3]      _
        [int3]      _
        [int3]      _
        [int3]      _
        [int3]      _
        [movabs]      r8, 0x4444444444444444
        [mov]      rax, r13
        [jmp]      rax
Second pt_load is found at 0xdb8
The binary has the pie !
Entry point overwritten : 0x201028
Scnd pt_load offset : 0xdb8
Scnd pt_load filesz : 0x270
[*] Generating a new test_.p4cked executable file
Bytes injected at 0x2010c8: 
        4c8d2df9ffffff488b7c248415049b8281020000004d29c5415841555053515255575641504151415241534889e54881ec90000488d34244989f74989fcb82000be0000bafd100f5504889c74c89feb85000f54831ff498b7730ba300041ba20004158415041b90000b89000f557565150415041515048bf2810000000481f84889c648b92a200000049b90cccccccccccccc4981c1cc00048ad4883ee74c31c84883f8074ce2efb83c0004831fff5448a4694883c694989f648b83050000005e50481c65648b9a21000000514889f7ac4430c0aae2f9595f415a4889fef31481c251ac30d0aae2fa5941881648be688000000488b7d58491fa4152415051ba7000b8a000f5594158584889c64889c7ac4430c0aae2f94159415858595e5f4d8b5f305e4153504989f64c89e75e5a52565652686e61736d488d3c24b82000be42000bafd100f54883c484989c14889c7b810005a5ef54c89c84989c54c89f75e5a574889f74889d6b8b000f55fb83000f5b8570004c89e7f5b830004c89eff5b856000686e61736d488d3c244c89e6f5b857000488d3c24f54881c4900004889ec415b415a415941585e5f5d5a595b58415d48be305000000491f5eb8cccccccccccccccc49b8b100000004c89e8ffe0
Length of the stub : 0x22a
```

The binary test_.p4cked is now poly/metamorphic : 

```bash

mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:39]
$ md5sum ./test_.p4cked 
6d7b189d6db97e5ee4ce734d707ca2df  ./test_.p4cked
mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:39]
$ ./test_.p4cked 
If you can see it, it's that the injection has worked !!
mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:39]
$ md5sum ./test_.p4cked 
4a221a7b25ef9642bb4184c966d203a1  ./test_.p4cked
mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:40]
$ ./test_.p4cked 
If you can see it, it's that the injection has worked !!
mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:40]
$ md5sum ./test_.p4cked 
e0ed77593c456bd3ac046687c8c39572  ./test_.p4cked
mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:40]
$ ./test_.p4cked 
If you can see it, it's that the injection has worked !!
mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:40]
$ md5sum ./test_.p4cked 
862c27ce146932c5911dc81fc88f5bb9  ./test_.p4cked
mov @ REsearch ~/prog_/prog/C-C++/AD_1DA [03:40]
$ ./test_.p4cked 
If you can see it, it's that the injection has worked !!
 ```

# Preview

Metamorphic injection with pie : 

![](meta.gif)

# Work in progress ..

Discord -> https://discord.gg/x9Ute4a

## Requirements

[Libcapstone](https://www.capstone-engine.org/)

[Libkeystone](http://www.keystone-engine.org/)


## License
[GPL](https://www.gnu.org/licenses/gpl-3.0.fr.html)
