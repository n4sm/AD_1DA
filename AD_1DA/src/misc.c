#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <gelf.h>
#include <stdarg.h>
#include <getopt.h>
#include <ctype.h>

#include "include/include.h"
#include "include/misc.h"

#include <capstone/capstone.h>
#include <keystone/keystone.h> 

int exit_clean(unsigned char *text_stub){
    free(text_stub);
    return 0;
}

void log_ad(const char *s, int code) {
        if (code == SUCCESS)
            printf( "[+] "
                    "%s", s);
        else if (code == FAILURE)
            fprintf(stderr,
                   "[_] "
                    "%s", s);
    }

int dump_struct(void *s, short type) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)s;
    Elf64_Ehdr *eh_ptr = (Elf64_Ehdr *)s;

    switch (type) {
        case Elf64_EHDR:
            printf(     "\tElf64_Ehdr {\n"
                            "\t\t.e_type = 0x%x\n"
                            "\t\t.e_machine = 0x%x\n"
                            "\t\t.e_version = 0x%x\n"
                            "\t\t.e_entry = 0x%lx\n"
                            "\t\t.e_phoff = 0x%lx\n"
                            "\t\t.e_shoff = 0x%lx\n"
                            "\t\t.e_flags = 0x%x\n"
                            "\t\t.e_ehsize = 0x%x\n"
                            "\t\t.e_phentsize = 0x%x\n"
                            "\t\t.e_phnum = 0x%x\n"
                            "\t\t.e_shentsize = 0x%x\n"
                            "\t\t.e_shnum = 0x%x\n"
                            "\t\t.e_shstrndx = 0x%x\n"
                         "\t};\n", eh_ptr->e_type, eh_ptr->e_machine,
                           eh_ptr->e_version, eh_ptr->e_entry,
                           eh_ptr->e_phoff, eh_ptr->e_shoff,
                           eh_ptr->e_flags, eh_ptr->e_ehsize,
                           eh_ptr->e_phentsize, eh_ptr->e_phnum,
                           eh_ptr->e_shentsize, eh_ptr->e_shnum,
                           eh_ptr->e_shstrndx);

        case Elf64_PHDR:
            printf(  "\tElf64_Phdr {\n"
                        "\t\t.p_type = 0x%x\n"
                        "\t\t.p_flags = 0x%x\n"
                        "\t\t.p_offset = 0x%lx\n"
                        "\t\t.p_vaddr = 0x%lx\n"
                        "\t\t.p_paddr = 0x%lx\n"
                        "\t\t.p_filesz = 0x%lx\n"
                        "\t\t.p_memsz = 0x%lx\n"
                        "\t\t.p_align = 0x%lx\n"
                     "\t};\n", phdr->p_type, phdr->p_flags,
                     phdr->p_offset, phdr->p_vaddr,
                     phdr->p_filesz, phdr->p_filesz,
                     phdr->p_memsz, phdr->p_align);
        default:
            return -1;
    }

    return 0;
}

int dump_file(const char *name, unsigned char *to_dump, ssize_t len_dump) {
    int fd = open(name,  O_RDWR | O_CREAT, 0777);

    if (fd == -1) {
        perror("[ERROR] open\n");
        close(fd);

        return -1;
    }

    // We write all our malloc in the file

    write(fd, to_dump, len_dump);
    log_ad("", SUCCESS);
    printf("%s created\n", name);

    return 0;
}

/*
 *
 * typedef struct
 * {
 *  Elf64_Word	p_type;
 *  Elf64_Word	p_flags;
 *  Elf64_Off	p_offset;
 *  Elf64_Addr	p_vaddr;
 *  Elf64_Addr	p_paddr;
 *  Elf64_Xword	p_filesz;
 *  Elf64_Xword	p_memsz;
 *  Elf64_Xword	p_align;
 * } Elf64_Phdr;
 *
 * */

/*
typedef struct
{
    unsigned char	e_ident[EI_NIDENT];
    Elf64_Half	e_type;
    Elf64_Half	e_machine;
    Elf64_Word	e_version;
    Elf64_Addr	e_entry;
    Elf64_Off	e_phoff;
    Elf64_Off	e_shoff;
    Elf64_Word	e_flags;
    Elf64_Half	e_ehsize;
    Elf64_Half	e_phentsize;
    Elf64_Half	e_phnum;
    Elf64_Half	e_shentsize;
    Elf64_Half	e_shnum;
    Elf64_Half	e_shstrndx;
} Elf64_Ehdr;
*/