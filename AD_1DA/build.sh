#!/bin/bash
gcc *.c -o main -lbfd -lkeystone -lstdc++ -lm -lcapstone -g && chmod +x regen.sh && chmod +x demo.sh && ./regen.sh && nasm -f elf64 test.asm -o test.o && ld test.o -o test && ./test
