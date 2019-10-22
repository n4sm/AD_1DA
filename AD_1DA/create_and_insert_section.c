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

#include "include.h"

#include <keystone/keystone.h>
#include <capstone/capstone.h>

// ==========================================================================================================================
// =================================    Functions which insert and create a section =========================================
// ==========================================================================================================================


// ==========================================================================================================================


int create_new_section(const char *filename, ssize_t len_sec, const char *name_sec){

    flagword _flags_ = 0x7;
    bfd_size_type val_sec_len = len_sec;

    bfd_init();

    bfd *elf_target = bfd_openw(filename, "x86_64-pc-linux-gnu");

    asection *section_created = bfd_make_section(elf_target, name_sec);

    if (!bfd_set_section_flags(elf_target, section_created, _flags_))
    {
        perror("[ERROR] Set flags has failed\n");
        return -1;
    }

    if (!bfd_set_section_size(elf_target, section_created, val_sec_len))
    {
        perror("[ERROR] Set size has failed\n");
        return -1;
    }

    if(bfd_close(elf_target))
        perror("[ERROR] bfclose\n");

    return 0;
}

// ==========================================================================================================================


unsigned char *m_new_section(Elf64_Ehdr *target_pt_load,  unsigned char *target_scnd_pt_load, Elf64_Phdr *buffer_mdata_ph[], ssize_t sz_sec, ssize_t len_target_file, ssize_t len_data){

    // **********************************************************

    Elf64_Shdr n_sec = {
        .sh_name = (uint32_t)0,
        .sh_type = (uint32_t)SHT_PROGBITS,
        .sh_flags = (uint64_t)SHF_EXECINSTR | SHF_ALLOC,
        .sh_addr = (Elf64_Addr)0,
        .sh_offset = (Elf64_Off)0,
        .sh_size = (uint64_t)0,
        .sh_link = (uint32_t)0,
        .sh_info = (uint32_t)0,
        .sh_addralign = (uint64_t)16,
        .sh_entsize = (uint64_t)0,
    };

    // **********************************************************

    Elf64_Phdr *tmp_phdr = (Elf64_Phdr *)(target_pt_load + target_pt_load->e_ehsize);

    

    Elf64_Phdr *phdr_pt_load = search_fst_pt_load(target_pt_load, buffer_mdata_ph);


    // On realloc d'abord la sct header table

    target_pt_load->e_shnum += 1;
    ssize_t len_r_sec = len_data;

    if(!realloc(target_scnd_pt_load, len_r_sec + (target_pt_load->e_shnum * sizeof(Elf64_Shdr)))){
        printf("[ERROR] Fatal realloc\n");
        exit(-1);
    }

    // ===========

    // On realloc d'abord la .text

    tmp_phdr->p_filesz += sz_sec;
    tmp_phdr->p_memsz += sz_sec;

    if(!realloc(target_pt_load, target_pt_load->e_ehsize + target_pt_load->e_phnum * target_pt_load->e_phentsize + phdr_pt_load->p_filesz)){
        printf("[ERROR] Fatal realloc\n");
        exit(-1);
    }

    // ===========

    if (!has_pie_or_not(buffer_mdata_ph, target_pt_load))
    {
        n_sec.sh_addr = 0x0;
    }
    else
    {
        n_sec.sh_addr = phdr_pt_load->p_vaddr + phdr_pt_load->p_memsz;
    }
    
    n_sec.sh_offset = target_pt_load->e_ehsize + target_pt_load->e_phnum * target_pt_load->e_phentsize + phdr_pt_load->p_filesz;
    n_sec.sh_size = sz_sec;

    // ===========


    // On memcpy notre section header

    memcpy(target_scnd_pt_load + len_r_sec + sizeof(Elf64_Shdr) * (target_pt_load->e_shnum - 1), &n_sec, sizeof(Elf64_Shdr));

    // ===========

    // ssize_t len_data = (target_phdr->p_offset + target_phdr->p_filesz + sz_sec) - eh_ptr->e_shoff;

    // Mtn faut tout dumper

    unsigned char *dumped_data = malloc(len_target_file + sizeof(Elf64_Shdr) + sz_sec);

    // Et là on fait dla merd

    // 1st le executable header

    memcpy(dumped_data, target_pt_load, target_pt_load->e_ehsize + target_pt_load->e_phnum * target_pt_load->e_phentsize + phdr_pt_load->p_filesz);

    // 3rd notre section edit

    unsigned char *scnd_dumped_pt_load = memcpy(dumped_data + target_pt_load->e_ehsize + target_pt_load->e_phnum * target_pt_load->e_phentsize + phdr_pt_load->p_filesz, target_scnd_pt_load, len_data + sizeof(Elf64_Shdr) * target_pt_load->e_shnum);

    return dumped_data;

}

// ===========================================================================================================


int inject_section(unsigned char *buffer_bytes, ssize_t buffer_len, unsigned char *address_to_inject, Elf64_Phdr *phdr_fst_pt_load, Elf64_Ehdr *eh_ptr){

    for (size_t i = 0; i < buffer_len; i++)
    {
        *(address_to_inject + eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz + i) = *(buffer_bytes + i);
    }

    return 0;
}

// ===========================================================================================================

int rename_target_section(Elf64_Ehdr *eh_ptr, Elf64_Phdr *buffer_mdata_ph[], Elf64_Shdr *buffer_mdata_sh[], unsigned char *file_ptr, Elf64_Shdr *target_shdr){

    off_t offset = 0;
	Elf64_Shdr *shstrtab_header;

    shstrtab_header = (Elf64_Shdr *)((char *)file_ptr + eh_ptr->e_shoff + eh_ptr->e_shentsize * eh_ptr->e_shstrndx);

    char *shstrndx = (char *)file_ptr + shstrtab_header->sh_offset;

    char *shstrndx_saved = (char *)file_ptr + shstrtab_header->sh_offset;

    int len_all_name = shstrtab_header->sh_size;

    for (size_t i = 0; i < shstrtab_header->sh_size; i++)
    {
        shstrndx[i] = 0x2e;
    }

    shstrndx[eh_ptr->e_shnum] = 0x0;

    for (size_t i = 0; i < eh_ptr->e_shnum; i++)
    {
        buffer_mdata_sh[i]->sh_name = 0x1;
    }

    return 0;
}

// ===================================================================================================================================

int rewrite_ep(Elf64_Ehdr *eh_ptr, Elf64_Phdr *buffer_mdata_ph[], Elf64_Shdr *buffer_mdata_sh[], unsigned char *address_to_inject){

    Elf64_Ehdr *eh_ptr_tmp = (Elf64_Ehdr *)address_to_inject;

    Elf64_Phdr *fst_tmp_phdr = search_fst_pt_load(eh_ptr, buffer_mdata_ph);

    eh_ptr_tmp->e_entry = eh_ptr_tmp->e_ehsize + eh_ptr_tmp->e_phnum * eh_ptr_tmp->e_phentsize + fst_tmp_phdr->p_filesz;

    printf("Entry point rewritten -> 0x%lx\n", eh_ptr_tmp->e_entry);

    return 0;
}

// ===================================================================================================================================

unsigned char *m_extend_code(Elf64_Ehdr *target_pt_load,  unsigned char *target_scnd_pt_load, Elf64_Phdr *buffer_mdata_ph[], ssize_t sz_sec, ssize_t len_target_file, ssize_t len_data){

    Elf64_Phdr *tmp_phdr = (Elf64_Phdr *)(target_pt_load + target_pt_load->e_ehsize); // juste le début de notre phdr table

    Elf64_Phdr *phdr_pt_load = search_fst_pt_load(target_pt_load, buffer_mdata_ph);

    // ===========

    // On realloc d'abord la .text

    tmp_phdr->p_filesz += sz_sec;
    tmp_phdr->p_memsz += sz_sec;

    if(!realloc(target_pt_load, target_pt_load->e_ehsize + target_pt_load->e_phnum * target_pt_load->e_phentsize + tmp_phdr->p_filesz)){
        printf("[ERROR] Fatal realloc\n");
        exit(-1);
    }

    // ===========

    // ssize_t len_data = (target_phdr->p_offset + target_phdr->p_filesz + sz_sec) - eh_ptr->e_shoff;

    // Mtn faut tout dumper

    unsigned char *dumped_data = malloc(len_target_file + sz_sec);

    // Et là on fait dla merd

    // 1st le executable header

    memcpy(dumped_data, target_pt_load, target_pt_load->e_ehsize + target_pt_load->e_phnum * target_pt_load->e_phentsize + phdr_pt_load->p_filesz);

    // 3rd notre section edit

    memcpy(dumped_data + target_pt_load->e_ehsize + target_pt_load->e_phnum * target_pt_load->e_phentsize + phdr_pt_load->p_filesz, target_scnd_pt_load, len_data);

    return dumped_data;


    return 0;
}