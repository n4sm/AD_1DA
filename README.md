[![forthebadge](https://forthebadge.com/images/badges/made-with-c.svg)](https://forthebadge.com)

# AD_1DA

Another linux obfuscator that creates at each execution a new packed version of itself to avoid code signatures.

# Installation

```bash
git clone https://github.com/n4sm/AD_1DA
cd AD_1DA/AD_1DA && make
```

# Usage

```bash
$ ./main
Usage ./main <target> (option) *stub* |layer|
Options:
	-o: Injection and basic patching
	-m: Injection and self modification
stub:
	You can use either your stub or default stub => stub/
layer:
	Number of layer you want for the final binary (base 16)
```

For example with a PIE based binary with the use of the stub/meta_stub_hook.asm stub with 10 layers of packing:

```bash
$ ./main test_folder/test_c -m stub/meta_stub_hook 10
Raw executables bytes in the stub : 
	4c8d2df9ffffff488b7c248415049b833333333333333334d29c5415841555053515255575641504151415241534889e54881ec90000488d34244989f74989fcb82000be0000bafd100f5504889c74c89feb85000f54831ff498b7730ba300041ba20004158415041b90000b89000f557565150415041515048bf6666666666666666481f84889c648b955555555555555554d31c949b90cccccccccccccc4981c1cc00048ad4883ee74c31c84883f80747e2efe94e200448a4694883c694989f648b811111111111111115e50481c65648b98888888888888888514889f7ac4430c0aae2f9595f415a4889fe4831c0505756514883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000b82000488d3c24be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c484883c410595e5f58514831c0ac30d0aae2fa5941881648be777777777777777748bf9999999999999999565751504829f74889f9488b8548ffffff481c64889f74883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000565751b82000488d7c2418be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c48595f5eac30d0aae2bc4883c41058595f5e488b7d58491fa4152415051ba7000b8a000f5594158584889c64889c7ac4430c0aae2f94159415858595e5f4d8b5f305e4153504989f64c89e75e5a52565652686e61736d488d3c24b82000be42000bafd100f54883c484989c14889c7b810005a5ef54c89c84989c54c89f75e5a574889f74889d6b8b000f55fb83000f5b8570004c89e7f5b830004c89eff5b856000686e61736d488d3c244c89e6f5b857000488d3c24f54881c4900004889ec415b415a415941585e5f5d5a595b58415d48be1010101010101010491f5eb8cccccccccccccccc49b844444444444444444c89e8ffe0b83c000bfff000f5
Disassembling the stub : 
	[lea]		r13, qword ptr [rip - 7]
	[mov]		rdi, qword ptr [rsp + 8]
	[push]		r8
	[movabs]	r8, 0x3333333333333333
	[sub]		r13, r8
	[pop]		r8
	[push]		r13
	[push]		rax
	[push]		rbx
	[push]		rcx
	[push]		rdx
	[push]		rbp
	[push]		rdi
	[push]		rsi
	[push]		r8
	[push]		r9
	[push]		r10
	[push]		r11
	[mov]		rbp, rsp
	[sub]		rsp, 0x90
	[lea]		rsi, qword ptr [rsp]
	[mov]		r15, rsi
	[mov]		r12, rdi
	[mov]		eax, 2
	[mov]		esi, 0
	[mov]		edx, 0x1fd
	[syscall]	_
	[push]		rax
	[mov]		rdi, rax
	[mov]		rsi, r15
	[mov]		eax, 5
	[syscall]	_
	[xor]		rdi, rdi
	[mov]		rsi, qword ptr [r15 + 0x30]
	[mov]		edx, 3
	[mov]		r10d, 2
	[pop]		r8
	[push]		r8
	[mov]		r9d, 0
	[mov]		eax, 9
	[syscall]	_
	[push]		rdi
	[push]		rsi
	[push]		rcx
	[push]		rax
	[push]		r8
	[push]		r9
	[push]		rax
	[movabs]	rdi, 0x6666666666666666
	[add]		rax, rdi
	[mov]		rsi, rax
	[movabs]	rcx, 0x5555555555555555
	[xor]		r9, r9
	[movabs]	r9, 0xcccccccccccccc00
	[add]		r9, 0xcc
	[lodsq]		rax, qword ptr [rsi]
	[sub]		rsi, 7
	[xor]		rax, r9
	[cmp]		rax, 0
	[je]		0xd1
	[loop]		0xbb
	[jmp]		0x31f
	[mov]		r8b, byte ptr [rsi + 9]
	[add]		rsi, 9
	[mov]		r14, rsi
	[movabs]	rax, 0x1111111111111111
	[pop]		rsi
	[push]		rax
	[add]		rsi, rax
	[push]		rsi
	[movabs]	rcx, 0x8888888888888888
	[push]		rcx
	[mov]		rdi, rsi
	[lodsb]		al, byte ptr [rsi]
	[xor]		al, r8b
	[stosb]		byte ptr [rdi], al
	[loop]		0xfa
	[pop]		rcx
	[pop]		rdi
	[pop]		r10
	[mov]		rsi, rdi
	[xor]		rax, rax
	[push]		rax
	[push]		rdi
	[push]		rsi
	[push]		rcx
	[sub]		rsp, 0x10
	[mov]		dword ptr [rsp], 0x7665642f
	[mov]		dword ptr [rsp + 4], 0x6172752f
	[mov]		dword ptr [rsp + 8], 0x6d6f646e
	[mov]		dword ptr [rsp + 0xc], 0
	[mov]		eax, 2
	[lea]		rdi, qword ptr [rsp]
	[mov]		esi, 0
	[mov]		edx, 0x1fd
	[syscall]	_
	[mov]		rdi, rax
	[xor]		rax, rax
	[sub]		rsp, 8
	[lea]		rsi, qword ptr [rsp]
	[mov]		edx, 1
	[syscall]	_
	[mov]		dl, byte ptr [rsi]
	[mov]		eax, 3
	[syscall]	_
	[add]		rsp, 8
	[add]		rsp, 0x10
	[pop]		rcx
	[pop]		rsi
	[pop]		rdi
	[pop]		rax
	[push]		rcx
	[xor]		rax, rax
	[lodsb]		al, byte ptr [rsi]
	[xor]		al, dl
	[stosb]		byte ptr [rdi], al
	[loop]		0x175
	[pop]		rcx
	[mov]		byte ptr [r14], dl
	[movabs]	rsi, 0x7777777777777777
	[movabs]	rdi, 0x9999999999999999
	[push]		rsi
	[push]		rdi
	[push]		rcx
	[push]		rax
	[sub]		rdi, rsi
	[mov]		rcx, rdi
	[mov]		rax, qword ptr [rbp - 0xb8]
	[add]		rsi, rax
	[mov]		rdi, rsi
	[sub]		rsp, 0x10
	[mov]		dword ptr [rsp], 0x7665642f
	[mov]		dword ptr [rsp + 4], 0x6172752f
	[mov]		dword ptr [rsp + 8], 0x6d6f646e
	[mov]		dword ptr [rsp + 0xc], 0
	[push]		rsi
	[push]		rdi
	[push]		rcx
	[mov]		eax, 2
	[lea]		rdi, qword ptr [rsp + 0x18]
	[mov]		esi, 0
	[mov]		edx, 0x1fd
	[syscall]	_
	[mov]		rdi, rax
	[xor]		rax, rax
	[sub]		rsp, 8
	[lea]		rsi, qword ptr [rsp]
	[mov]		edx, 1
	[syscall]	_
	[mov]		dl, byte ptr [rsi]
	[mov]		eax, 3
	[syscall]	_
	[add]		rsp, 8
	[pop]		rcx
	[pop]		rdi
	[pop]		rsi
	[lodsb]		al, byte ptr [rsi]
	[xor]		al, dl
	[stosb]		byte ptr [rdi], al
	[loop]		0x1cd
	[add]		rsp, 0x10
	[pop]		rax
	[pop]		rcx
	[pop]		rdi
	[pop]		rsi
	[mov]		rdi, qword ptr [rbp + 0x58]
	[add]		r10, rdi
	[push]		r10
	[push]		r8
	[push]		rcx
	[mov]		edx, 7
	[mov]		eax, 0xa
	[syscall]	_
	[pop]		rcx
	[pop]		r8
	[pop]		rax
	[mov]		rsi, rax
	[mov]		rdi, rax
	[lodsb]		al, byte ptr [rsi]
	[xor]		al, r8b
	[stosb]		byte ptr [rdi], al
	[loop]		0x23b
	[pop]		r9
	[pop]		r8
	[pop]		rax
	[pop]		rcx
	[pop]		rsi
	[pop]		rdi
	[mov]		r11, qword ptr [r15 + 0x30]
	[pop]		rsi
	[push]		r11
	[push]		rax
	[mov]		r14, rsi
	[mov]		rdi, r12
	[pop]		rsi
	[pop]		rdx
	[push]		rdx
	[push]		rsi
	[push]		rsi
	[push]		rdx
	[push]		0x6d73616e
	[lea]		rdi, qword ptr [rsp]
	[mov]		eax, 2
	[mov]		esi, 0x42
	[mov]		edx, 0x1fd
	[syscall]	_
	[add]		rsp, 8
	[mov]		r9, rax
	[mov]		rdi, rax
	[mov]		eax, 1
	[pop]		rdx
	[pop]		rsi
	[syscall]	_
	[mov]		rax, r9
	[mov]		r13, rax
	[mov]		rdi, r14
	[pop]		rsi
	[pop]		rdx
	[push]		rdi
	[mov]		rdi, rsi
	[mov]		rsi, rdx
	[mov]		eax, 0xb
	[syscall]	_
	[pop]		rdi
	[mov]		eax, 3
	[syscall]	_
	[mov]		eax, 0x57
	[mov]		rdi, r12
	[syscall]	_
	[mov]		eax, 3
	[mov]		rdi, r13
	[syscall]	_
	[mov]		eax, 0x56
	[push]		0x6d73616e
	[lea]		rdi, qword ptr [rsp]
	[mov]		rsi, r12
	[syscall]	_
	[mov]		eax, 0x57
	[lea]		rdi, qword ptr [rsp]
	[syscall]	_
	[add]		rsp, 0x90
	[mov]		rsp, rbp
	[pop]		r11
	[pop]		r10
	[pop]		r9
	[pop]		r8
	[pop]		rsi
	[pop]		rdi
	[pop]		rbp
	[pop]		rdx
	[pop]		rcx
	[pop]		rbx
	[pop]		rax
	[pop]		r13
	[movabs]	rsi, 0x1010101010101010
	[add]		r13, rsi
	[jmp]		0x310
	[int3]		_
	[int3]		_
	[int3]		_
	[int3]		_
	[int3]		_
	[int3]		_
	[int3]		_
	[int3]		_
	[movabs]	r8, 0x4444444444444444
	[mov]		rax, r13
	[jmp]		rax
	[mov]		eax, 0x3c
	[mov]		edi, 0xff
	[syscall]	_
[+] Working on: test_folder/test_c
Working on 0x0 mutation => test_folder/test_c
[+] PT_DYN:
	Elf64_Phdr {
		.p_type = 0x2
		.p_flags = 0x6
		.p_offset = 0x2da8
		.p_vaddr = 0x3da8
		.p_paddr = 0x1f0
		.p_filesz = 0x1f0
		.p_memsz = 0x1f0
		.p_align = 0x8
	};
[+] garbage PT_LOAD:
	Elf64_Phdr {
		.p_type = 0x1
		.p_flags = 0x4
		.p_offset = 0x2000
		.p_vaddr = 0x2000
		.p_paddr = 0x160
		.p_filesz = 0x160
		.p_memsz = 0x160
		.p_align = 0x1000
	};
[+] last PT_LOAD:
	Elf64_Phdr {
		.p_type = 0x1
		.p_flags = 0x6
		.p_offset = 0x2d98
		.p_vaddr = 0x3d98
		.p_paddr = 0x27c
		.p_filesz = 0x27c
		.p_memsz = 0x280
		.p_align = 0x1000
	};
[+] gap between last_pt_load and the stub: 0x4
[+] Target executable memory area offt: 0x1000 (memory), 0x1000 (file)
[+] The binary PIE based!
[+] patch_target: 0x3333333333333333 => 0x4018
[+] patch_target: 0x1010101010101010 => 0x10e0
[+] Virtual address of the stub: 0x4018
[+] Entry point patched: 0x10e0 => 0x4018
[+] Code cave length: 0xc38
[+] patch_target: 0x4444444444444444 => 0x50
[+] patch_target: 0x5555555555555555 => 0x32b
[+] patch_target: 0x6666666666666666 => 0x3018
[+] patch_target: 0x7777777777777777 => 0x2160
[+] patch_target: 0x1111111111111111 => 0x1000
[+] patch_target: 0x8888888888888888 => 0x2d5
[+] patch_target: 0x9999999999999999 => 0x2d98
[+] Number of mutations: 0xc3900
[+] Bytes injected at 0x3018:
	4c8d2df9ffffff488b7c248415049b818400000004d29c5415841555053515255575641504151415241534889e54881ec90000488d34244989f74989fcb82000be0000bafd100f5504889c74c89feb85000f54831ff498b7730ba300041ba20004158415041b90000b89000f557565150415041515048bf1830000000481f84889c648b92b30000004d31c949b90cccccccccccccc4981c1cc00048ad4883ee74c31c84883f80747e2efe94e200448a4694883c694989f648b80100000005e50481c65648b9d52000000514889f7ac4430c0aae2f9595f415a4889fe4831c0505756514883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000b82000488d3c24be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c484883c410595e5f58514831c0ac30d0aae2fa5941881648be602100000048bf982d000000565751504829f74889f9488b8548ffffff481c64889f74883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000565751b82000488d7c2418be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c48595f5eac30d0aae2bc4883c41058595f5e488b7d58491fa4152415051ba7000b8a000f5594158584889c64889c7ac4430c0aae2f94159415858595e5f4d8b5f305e4153504989f64c89e75e5a52565652686e61736d488d3c24b82000be42000bafd100f54883c484989c14889c7b810005a5ef54c89c84989c54c89f75e5a574889f74889d6b8b000f55fb83000f5b8570004c89e7f5b830004c89eff5b856000686e61736d488d3c244c89e6f5b857000488d3c24f54881c4900004889ec415b415a415941585e5f5d5a595b58415d48bee010000000491f5eb8cccccccccccccccc49b85000000004c89e8ffe0b83c000bfff000f5
[+] Stub length: 0x32b
Working on 0xe mutation => test_folder/test_c
[+] PT_DYN:
	Elf64_Phdr {
		.p_type = 0x2
		.p_flags = 0x6
		.p_offset = 0x2da8
		.p_vaddr = 0x3da8
		.p_paddr = 0x1f0
		.p_filesz = 0x1f0
		.p_memsz = 0x1f0
		.p_align = 0x8
	};
[+] garbage PT_LOAD:
	Elf64_Phdr {
		.p_type = 0x1
		.p_flags = 0x4
		.p_offset = 0x2000
		.p_vaddr = 0x2000
		.p_paddr = 0x160
		.p_filesz = 0x160
		.p_memsz = 0x160
		.p_align = 0x1000
	};
[+] last PT_LOAD:
	Elf64_Phdr {
		.p_type = 0x1
		.p_flags = 0x7
		.p_offset = 0x2d98
		.p_vaddr = 0x3d98
		.p_paddr = 0x2eda
		.p_filesz = 0x2eda
		.p_memsz = 0x2eda
		.p_align = 0x1000
	};
[+] gap between last_pt_load and the stub: 0x0
[+] Target executable memory area offt: 0x1000 (memory), 0x1000 (file)
[+] The binary PIE based!
[+] patch_target: 0x3333333333333333 => 0x6c72
[+] patch_target: 0x1010101010101010 => 0x6947
[+] Virtual address of the stub: 0x6c72
[+] Entry point patched: 0x6947 => 0x6c72
[+] Code cave length: 0xc38
[+] patch_target: 0x4444444444444444 => 0xfa
[+] patch_target: 0x5555555555555555 => 0x32b
[+] patch_target: 0x6666666666666666 => 0x5c72
[+] patch_target: 0x7777777777777777 => 0x2160
[+] patch_target: 0x1111111111111111 => 0x1000
[+] patch_target: 0x8888888888888888 => 0x2d5
[+] patch_target: 0x9999999999999999 => 0x2d98
[+] Number of mutations: 0xc3900
[+] Bytes injected at 0x5c72:
	4c8d2df9ffffff488b7c248415049b8726c0000004d29c5415841555053515255575641504151415241534889e54881ec90000488d34244989f74989fcb82000be0000bafd100f5504889c74c89feb85000f54831ff498b7730ba300041ba20004158415041b90000b89000f557565150415041515048bf725c000000481f84889c648b92b30000004d31c949b90cccccccccccccc4981c1cc00048ad4883ee74c31c84883f80747e2efe94e200448a4694883c694989f648b80100000005e50481c65648b9d52000000514889f7ac4430c0aae2f9595f415a4889fe4831c0505756514883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000b82000488d3c24be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c484883c410595e5f58514831c0ac30d0aae2fa5941881648be602100000048bf982d000000565751504829f74889f9488b8548ffffff481c64889f74883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000565751b82000488d7c2418be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c48595f5eac30d0aae2bc4883c41058595f5e488b7d58491fa4152415051ba7000b8a000f5594158584889c64889c7ac4430c0aae2f94159415858595e5f4d8b5f305e4153504989f64c89e75e5a52565652686e61736d488d3c24b82000be42000bafd100f54883c484989c14889c7b810005a5ef54c89c84989c54c89f75e5a574889f74889d6b8b000f55fb83000f5b8570004c89e7f5b830004c89eff5b856000686e61736d488d3c244c89e6f5b857000488d3c24f54881c4900004889ec415b415a415941585e5f5d5a595b58415d48be4769000000491f5eb8cccccccccccccccc49b8fa00000004c89e8ffe0b83c000bfff000f5
[+] Stub length: 0x32b
Working on 0xf mutation => test_folder/test_c
[+] PT_DYN:
	Elf64_Phdr {
		.p_type = 0x2
		.p_flags = 0x6
		.p_offset = 0x2da8
		.p_vaddr = 0x3da8
		.p_paddr = 0x1f0
		.p_filesz = 0x1f0
		.p_memsz = 0x1f0
		.p_align = 0x8
	};
[+] garbage PT_LOAD:
	Elf64_Phdr {
		.p_type = 0x1
		.p_flags = 0x4
		.p_offset = 0x2000
		.p_vaddr = 0x2000
		.p_paddr = 0x160
		.p_filesz = 0x160
		.p_memsz = 0x160
		.p_align = 0x1000
	};
[+] last PT_LOAD:
	Elf64_Phdr {
		.p_type = 0x1
		.p_flags = 0x7
		.p_offset = 0x2d98
		.p_vaddr = 0x3d98
		.p_paddr = 0x3205
		.p_filesz = 0x3205
		.p_memsz = 0x3205
		.p_align = 0x1000
	};
[+] gap between last_pt_load and the stub: 0x0
[+] Target executable memory area offt: 0x1000 (memory), 0x1000 (file)
[+] The binary PIE based!
[+] patch_target: 0x3333333333333333 => 0x6f9d
[+] patch_target: 0x1010101010101010 => 0x6c72
[+] Virtual address of the stub: 0x6f9d
[+] Entry point patched: 0x6c72 => 0x6f9d
[+] Code cave length: 0xc38
[+] patch_target: 0x4444444444444444 => 0x4c
[+] patch_target: 0x5555555555555555 => 0x32b
[+] patch_target: 0x6666666666666666 => 0x5f9d
[+] patch_target: 0x7777777777777777 => 0x2160
[+] patch_target: 0x1111111111111111 => 0x1000
[+] patch_target: 0x8888888888888888 => 0x2d5
[+] patch_target: 0x9999999999999999 => 0x2d98
[+] Number of mutations: 0xc3900
[+] Bytes injected at 0x5f9d:
	4c8d2df9ffffff488b7c248415049b89d6f0000004d29c5415841555053515255575641504151415241534889e54881ec90000488d34244989f74989fcb82000be0000bafd100f5504889c74c89feb85000f54831ff498b7730ba300041ba20004158415041b90000b89000f557565150415041515048bf9d5f000000481f84889c648b92b30000004d31c949b90cccccccccccccc4981c1cc00048ad4883ee74c31c84883f80747e2efe94e200448a4694883c694989f648b80100000005e50481c65648b9d52000000514889f7ac4430c0aae2f9595f415a4889fe4831c0505756514883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000b82000488d3c24be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c484883c410595e5f58514831c0ac30d0aae2fa5941881648be602100000048bf982d000000565751504829f74889f9488b8548ffffff481c64889f74883ec10c74242f646576c7442442f757261c7442486e646f6dc74424c0000565751b82000488d7c2418be0000bafd100f54889c74831c04883ec8488d3424ba1000f58a16b83000f54883c48595f5eac30d0aae2bc4883c41058595f5e488b7d58491fa4152415051ba7000b8a000f5594158584889c64889c7ac4430c0aae2f94159415858595e5f4d8b5f305e4153504989f64c89e75e5a52565652686e61736d488d3c24b82000be42000bafd100f54883c484989c14889c7b810005a5ef54c89c84989c54c89f75e5a574889f74889d6b8b000f55fb83000f5b8570004c89e7f5b830004c89eff5b856000686e61736d488d3c244c89e6f5b857000488d3c24f54881c4900004889ec415b415a415941585e5f5d5a595b58415d48be726c000000491f5eb8cccccccccccccccc49b84c00000004c89e8ffe0b83c000bfff000f5
[+] Stub length: 0x32b
[+] test_folder/test_c.x created
```

 ```
$ ./test_folder/demo.sh test_folder/test_c.x                                                                                                          ✹ ✭master 
  1 md5 : cb49e9b2906fd55778a01545b100d075  test_folder/test_c.x
  2 md5 : 39253b98c5d6937d129754482c7831ce  test_folder/test_c.x
  3 md5 : f2647206f30f71064d62a1a425de1cd2  test_folder/test_c.x
  4 md5 : 31edccf3740d8b5850850e432ad6019e  test_folder/test_c.x
  5 md5 : 7035f8a13c738c8b2424f6f1150786ba  test_folder/test_c.x
  6 md5 : 6d8ff112336480341c70c473df6299cb  test_folder/test_c.x
  7 md5 : 3e553ecc165ed66934f7d63f07b2cdd8  test_folder/test_c.x
  8 md5 : 62598a01a2f4bb2ec0b941b1133d0b8f  test_folder/test_c.x
  9 md5 : abe0498cf9a071fb7725ee5a36996678  test_folder/test_c.x
 ```

# Work in progress ..

Discord -> https://ret2school.github.io/discord.html 

# Requirements

[Libcapstone](https://www.capstone-engine.org/)

# License

[GPL](https://www.gnu.org/licenses/gpl-3.0.fr.html)
