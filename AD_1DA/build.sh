gcc *.c -o main -lbfd -lkeystone -lstdc++ -lm -lcapstone -g && ./regen.sh && nasm -f elf64 test.asm -o test.o && ld test.o -o test && ./test
