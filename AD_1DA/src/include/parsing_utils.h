#ifndef AD_1DA_INCLUDE_H
#define AD_1DA_INCLUDE_H

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

#include <keystone/keystone.h>
#include <capstone/capstone.h>

#include "misc.h"
#include "binary.h"

// *=*=*=*=*=*= basic check

int is_elf(unsigned char *eh_ptr);

bool is_pie(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr);

// *=*=*=*=*=*= parsing

int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]);

int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]);

char **parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char **sh_name_buffer);

// *=*=*=*=*=*= utils

Elf64_Phdr *search_fst_pt_load(Elf64_Ehdr *eh_ptr, Elf64_Phdr *ph_ptr[]);

off_t search_x_segment(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr, int *len_text);

off_t search_x_segment_ifile(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr, int *len_text);

int patch_target(void *p_entry, unsigned long pattern, int size, unsigned long patch);

uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *ptr);

off_t search_section(const char *section, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *ptr, int *i_sec);

off_t search_section_name(char *sh_name_buffer[], Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section, uint64_t *len_sec);

// *=*=*=*=*=*=

#endif //AD_1DA_INCLUDE_H