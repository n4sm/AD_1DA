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

// Bon bah faut tout refaire ..
// ui indeed

// ==========================================================================================================================
// =================================    Functions which insert and create a section =========================================
// ==========================================================================================================================


// ==========================================================================================================================

// Ca c'est un try d'un truc qui a pas marché .. x)

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


unsigned char *m_new_section(unsigned char *target_pt_load,  unsigned char *target_scnd_pt_load, Elf64_Phdr *buffer_mdata_ph[], ssize_t sz_sec, ssize_t len_target_file, ssize_t len_data){

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

    // len_data == tout ce ke y'a après le 2nd pt_load et qui du coup est pas mappé

    Elf64_Ehdr *eh_ptr = (Elf64_Ehdr *)target_pt_load;

    Elf64_Phdr *tmp_phdr[eh_ptr->e_phnum];

    parse_phdr(eh_ptr, tmp_phdr);

    Elf64_Phdr *phdr_pt_load = search_fst_pt_load((Elf64_Ehdr *)target_pt_load, buffer_mdata_ph);

    Elf64_Phdr *scnd_pt;

    for (size_t i = 0; i < eh_ptr->e_phnum; i++)
    {
        if (tmp_phdr[i]->p_type == PT_LOAD && tmp_phdr[i]->p_flags == 0x5)
        {
            continue;
        }
        else if (tmp_phdr[i]->p_type == PT_LOAD)
        {
            // On sait que c'est le deuxieme 

            tmp_phdr[i]->p_memsz += sz_sec; // Ducoup on change la taille du deuxieme pt_load car c'est là que on va inject la section
            tmp_phdr[i]->p_filesz += sz_sec;   
    
            tmp_phdr[i]->p_flags = 0x7;

            scnd_pt = tmp_phdr[i];

            break;
        }
        
    }

    eh_ptr->e_shoff += sz_sec;

    /*

    if(!realloc(target_pt_load, phdr_pt_load->p_filesz)){
        printf("[ERROR] Fatal realloc\n");
        exit(-1);
    }

    // A voir, pour l'instant je del pas ça

    */

    // ===========

    // ===========
    
    // ===========

    // Mtn faut tout dumper

    // On crée ce qui va etre le nouvel elf

    unsigned char *dumped_data = malloc(len_target_file + sz_sec);

    // On met tout ce qui va etre mappé plus l'espace pour notre code à inject

    memcpy(dumped_data, target_pt_load, len_target_file - len_data);

    // Et on met le reste après

    memcpy(dumped_data + len_target_file - len_data + sz_sec, target_scnd_pt_load, len_data);

    // Et on return un ptr que va falloir désallouer

    return dumped_data;

}

// ===========================================================================================================


int inject_section(unsigned char *buffer_bytes, ssize_t buffer_len, unsigned char *address_to_inject, off_t from_to_inject){

    for (size_t i = 0; i < buffer_len; i++)
    {
        *(address_to_inject + from_to_inject + i) = *(buffer_bytes + i);
    }

    return 0;
}

// ===========================================================================================================

// C'est plus utile mais tjrs intéressant à lire

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

    eh_ptr_tmp->e_entry = fst_tmp_phdr->p_filesz;

    printf("Entry point rewritten -> 0x%lx\n", eh_ptr_tmp->e_entry);

    return 0;
}

// ===================================================================================================================================


// On va craft tjrs un petit stub qui va mettre en exec un petite zone de code à un endroit donné

#define CODE_MPROTECT "MOV rax, 0x11111111; JMP rax"

unsigned char *craft_mprotect_memory(ssize_t *len_crafted_stub){

    ks_engine *ks;
    ks_err error;
    size_t count;
    unsigned char *encode;
    size_t size;

    printf("Crafting stub with keystone : \n");

    if((error = ks_open(KS_ARCH_X86, KS_MODE_64, &ks)) != KS_ERR_OK){
        printf("ERROR: failed on ks_open(), quit\n");
        return (unsigned char *)-1;
    }

    if (ks_asm(ks, CODE_MPROTECT, 0, &encode, &size, &count) != KS_ERR_OK)
    {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
    }
    else
    {
        printf("\t");

        for (size_t i = 0; i < size; i++)
        {
            printf("%2x ", *(encode + i));
        }

        printf("\n");

        ks_free(encode);
        ks_close(ks);

        *len_crafted_stub = size;

        return encode;
        
    }

    return NULL;
}