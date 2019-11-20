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
                ./main <target_binary> -o <stub to inject>: Basic obfuscation (in work)
                ./main <target_binary> --add-code-only <stub_to inject>: Add only the executable bytes at the end of the pt_load (not availaible)
                ./main <target_binary> --add-code-only --raw-data <stub_to inject>: * (not availaible)

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

# Work in progress ..

Discord -> https://discord.gg/x9Ute4a

## Requirements

[Libcapstone](https://www.capstone-engine.org/)

[Libkeystone](http://www.keystone-engine.org/)


## License
[GPL](https://www.gnu.org/licenses/gpl-3.0.fr.html)
