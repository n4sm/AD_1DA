all: stub/meta_stub_hook stub/meta_stub_hook_no_pie test_folder/test test_folder/test_c main run clean

stub/meta_stub_hook.o: stub/meta_stub_hook.asm
	nasm -f elf64 stub/meta_stub_hook.asm -o stub/meta_stub_hook.o

stub/meta_stub_hook: stub/meta_stub_hook.o
	ld stub/meta_stub_hook.o -o stub/meta_stub_hook

stub/meta_stub_hook_no_pie.o: stub/meta_stub_hook_no_pie.asm
	nasm -f elf64 stub/meta_stub_hook_no_pie.asm -o stub/meta_stub_hook_no_pie.o

stub/meta_stub_hook_no_pie:  stub/meta_stub_hook_no_pie.o
	ld stub/meta_stub_hook_no_pie.o -o stub/meta_stub_hook_no_pie

main: src/create_and_insert_section.c src/main_elf_functions.c src/misc.c src/packer_functions.c src/main.c
	gcc src/create_and_insert_section.c src/main_elf_functions.c src/misc.c src/packer_functions.c src/main.c -o main -lkeystone -lstdc++ -lm -lcapstone -g

test_folder/test.o: test_folder/test.asm
	nasm -f elf64 test_folder/test.asm -o test_folder/test.o

test_folder/test: test_folder/test.o
	ld test_folder/test.o -o test_folder/test

test_folder/test_c: test_folder/test.c
	gcc test_folder/test.c -o test_folder/test_c

run: stub/meta_stub_hook
	./main test_folder/test_c -m stub/meta_stub_hook 10

clean:
	rm stub/*.o | rm test_folder/*.o test_folder/test_c test_folder/*.x test_folder/test