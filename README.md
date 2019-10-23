[![forthebadge](https://forthebadge.com/images/badges/made-with-c.svg)](https://forthebadge.com)

# AD_1DA

AD_1DA is a modern tool made in order to obfuscate your elf binaries.

## Installation



```bash
git clone https://github.com/n4sm/AD_1DA
cd AD_1DA
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
                ./main <target_binary> -o <stub to inject>: Basic obfuscation
                ./main <target_binary> --add-code-only <stub_to inject>: Add only the executable bytes at the end of the pt_load
                ./main <target_binary> --add-code-only --raw-data <stub_to inject>: *

* The stub is automatically an elf but you can indicate the --raw-data options if you want to inject directly assembly instructions from your stub
```

Usage : 
```bash
$ ./main
Usage : ./main <target_file> <option> <stub_to_inject>
Help : ./main -h
```

Inject code : 
```bash
$ ./main test_ -o test
Raw executables bytes in the stub : 
        b81000bf1000686e61736d488d3424ba4000f5b81000bf10006aa488d3424ba1000f5b83c000bf0000f5
Disassembling the stub : 
        [mov]      eax, 1
        [mov]      edi, 1
        [push]      0x6d73616e
        [lea]      rsi, qword ptr [rsp]
        [mov]      edx, 4
        [syscall]      _
        [mov]      eax, 1
        [mov]      edi, 1
        [push]      0xa
        [lea]      rsi, qword ptr [rsp]
        [mov]      edx, 1
        [syscall]      _
        [mov]      eax, 0x3c
        [mov]      edi, 0
        [syscall]      _
Entry point rewritten -> 0xae0
[*] Generating a new test_.p4cked executable file
Bytes injected : 
        b81000bf1000686e61736d488d3424ba4000f5b81000bf10006aa488d3424ba1000f5b83c000bf0000f5
Length of the stub : 0x3d
```

The entry point will be overwritten and your target elf file will be hooked.

Inject code without adding section : 
```bash
$ ./main test_ --add-code-only test
Raw executables bytes in the stub : 
        b81000bf1000686e61736d488d3424ba4000f5b81000bf10006aa488d3424ba1000f5b83c000bf0000f5
Disassembling the stub : 
        [mov]      eax, 1
        [mov]      edi, 1
        [push]      0x6d73616e
        [lea]      rsi, qword ptr [rsp]
        [mov]      edx, 4
        [syscall]      _
        [mov]      eax, 1
        [mov]      edi, 1
        [push]      0xa
        [lea]      rsi, qword ptr [rsp]
        [mov]      edx, 1
        [syscall]      _
        [mov]      eax, 0x3c
        [mov]      edi, 0
        [syscall]      _
Entry point rewritten -> 0xae0
[*] Generating a new test_.p4cked executable file
Bytes injected : 
        b81000bf1000686e61736d488d3424ba4000f5b81000bf10006aa488d3424ba1000f5b83c000bf0000f5
Length of the stub : 0x3d
```
Inject code from assembly instructions in a file : 
```bash
$ echo "mov rax, 0; mov rdi, 0; syscall" > instructions.txt
$ ./main test_ --add-code-only --raw-data instructions.txt 
Instructions to inject : 
        mov rax, 0; mov rdi, 0; syscall
Instructions compiled : 
        48 c7 c0  0  0  0  0 48 c7 c7  0  0  0  0  f  5 
        48c7c0000048c7c70000f5
Entry point rewritten -> 0xae0
[*] Generating a new test_.p4cked executable file
Bytes injected : 
        48c7c0000048c7c70000f5
Length of the stub : 0x10
```

But for the moment it does not work xD

# Work in progress ..

Discord -> https://discord.gg/x9Ute4a

## Requirements

[Libcapstone](https://www.capstone-engine.org/)

[Libkeystone](http://www.keystone-engine.org/)


## License
[GPL](https://www.gnu.org/licenses/gpl-3.0.fr.html)
