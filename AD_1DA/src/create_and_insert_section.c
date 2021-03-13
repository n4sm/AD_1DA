#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
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
#include <elf.h>
#include <bfd.h>
#include <pthread.h>

#include "include/include.h"

#include <keystone/keystone.h>
#include <capstone/capstone.h>

int inject_section(unsigned char *buffer_bytes,
                   ssize_t buffer_len,
                   unsigned char *address_to_inject,
                   off_t from_to_inject) {
    for (size_t i = 0; i < buffer_len; i++) {
        *(address_to_inject + from_to_inject + i) = *(buffer_bytes + i);
    }

    return 0;
}

// *=*=*=*=*=*=

int rewrite_ep(Elf64_Ehdr *eh_ptr,
               Elf64_Phdr *buffer_mdata_ph[],
               Elf64_Shdr *buffer_mdata_sh[],
               unsigned char *address_to_inject) {

    Elf64_Ehdr *eh_ptr_tmp = (Elf64_Ehdr *)address_to_inject;

    Elf64_Phdr *fst_tmp_phdr = search_fst_pt_load(eh_ptr, buffer_mdata_ph);

    eh_ptr_tmp->e_entry = fst_tmp_phdr->p_filesz;

    printf("Entry point rewritten -> 0x%lx\n", eh_ptr_tmp->e_entry);

    return 0;
}
