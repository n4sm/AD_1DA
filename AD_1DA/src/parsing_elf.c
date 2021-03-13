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
#include <capstone/capstone.h>
#include <time.h> 

#include "include/parsing_utils.h"
#include "include/misc.h"

int patch_target(void *p_entry, unsigned long pattern, int size, unsigned long patch) {
	p_entry = (unsigned char *)p_entry;
	unsigned long result;
	bool s = false;

	for(int i = 0 ; i < size; i++) {
		result = *((unsigned long *)(p_entry+i)) ^ pattern;

		if(!result) {
            log_ad("patch_target: ", SUCCESS);
            printf("0x%lx => 0x%lx\n",  *((unsigned long *)(p_entry+i)), patch);
			*((unsigned long *)(p_entry+i)) = patch;
			s = true;
		}
	}

	if (!s) {
        log_ad("Pattern ", FAILURE);
        printf("0x%lx not found\n", pattern);
        return -1;
	}

    return 0;
}

// *=*=*=*=*=*=

Elf64_Phdr *search_pt_dyn(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr) {
    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_ph[i]->p_type == PT_DYNAMIC) {
            return buffer_mdata_ph[i];
        }
    }

    return 0;
}

// *=*=*=*=*=*=

// If we have a PT_NOTE or a PT_DYNAMIC we're good else
off_t search_x_segment(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr, int *len_text) {
    ssize_t max = 0;
    off_t offset = -1;
    Elf64_Phdr *pt_dyn = search_pt_dyn(buffer_mdata_ph, eh_ptr);

    unsigned long base_addr = search_base_addr(buffer_mdata_ph, eh_ptr);

	for (size_t i = 0; i < eh_ptr->e_phnum; i++) {
        if (buffer_mdata_ph[i]->p_type == PT_LOAD
                && buffer_mdata_ph[i]->p_memsz > max
                && buffer_mdata_ph[i]->p_flags & PF_X) {
            if (pt_dyn && buffer_mdata_ph[i]->p_vaddr
                                + buffer_mdata_ph[i]->p_filesz > pt_dyn->p_vaddr) {
                continue;
            }

            max = buffer_mdata_ph[i]->p_memsz;
            offset = buffer_mdata_ph[i]->p_vaddr;
        }
	}
	
	return offset - base_addr;
}

// *=*=*=*=*=*=

off_t search_x_segment_ifile(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr, int *len_text) {
    ssize_t max = 0;
    off_t offset = -1;
    Elf64_Phdr *pt_dyn = search_pt_dyn(buffer_mdata_ph, eh_ptr);

    for (size_t i = 0; i < eh_ptr->e_phnum; i++) {
        if (buffer_mdata_ph[i]->p_type == PT_LOAD
            && buffer_mdata_ph[i]->p_filesz > max
            && buffer_mdata_ph[i]->p_flags & PF_X
            && !(buffer_mdata_ph[i]->p_flags & PF_W)) {
            if (pt_dyn && buffer_mdata_ph[i]->p_vaddr
                    + buffer_mdata_ph[i]->p_filesz > pt_dyn->p_vaddr) {
                continue;
            }

            max = buffer_mdata_ph[i]->p_filesz;
            offset = buffer_mdata_ph[i]->p_offset;
        }
    }

    *len_text = max;
    return offset;
}


// *=*=*=*=*=*=

bool is_pie(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr) {
    int min = buffer_mdata_ph[0]->p_vaddr;

    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_ph[i]->p_vaddr < min
            && buffer_mdata_ph[i]->p_type == PT_LOAD) {
            min = buffer_mdata_ph[i]->p_vaddr;
        }
    }

    return min == 0;
}

// *=*=*=*=*=*=

off_t search_section_name(char *sh_name_buffer[], Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section, uint64_t *len_sec) {

    for (size_t i = 0; i < ptr->e_shnum; i++) {
        if (!strcmp(sh_name_buffer[i], section)) {
            *len_sec = buffer_mdata_sh[i]->sh_size;
            return buffer_mdata_sh[i]->sh_offset;
        }
    }
}

// *=*=*=*=*=*=

uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *eh_ptr) {
    unsigned long min = buffer_mdata_phdr[0]->p_vaddr;

    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_phdr[i]->p_type == PT_LOAD
             && buffer_mdata_phdr[i]->p_vaddr < min) {
            min = buffer_mdata_phdr[i]->p_vaddr;
        }
    }

	return min;
}

// *=*=*=*=*=*=

char **parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char *sh_name_buffer[ptr->e_shnum]) {
	Elf64_Shdr *shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr->e_shoff + ptr->e_shentsize * ptr->e_shstrndx));
	const char *shstrndx = (const char *)ptr + shstrtab_header->sh_offset;

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;
	}

	return sh_name_buffer;
}

// *=*=*=*=*=*=

int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]) {
	size_t number_of_sections = ptr->e_phnum;
	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_phnum; i++) {
		buffer_mdata_ph[i]  = (Elf64_Phdr *) ((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));
	}

	return 0;
}

// *=*=*=*=*=*=

int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]) {
	size_t number_of_sections = ptr->e_shnum;
	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		buffer_mdata_sh[i]  = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * i));
	}

	return 0;
}

// *=*=*=*=*=*=

off_t search_section(const char *section, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *ptr, int *i_sec) {
	off_t offset = 0;
	Elf64_Shdr *shstrtab_header;
	char *sh_name_buffer[ptr->e_shnum];
    const char *shstrndx = (const char *)ptr + shstrtab_header->sh_offset;

	shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr->e_shoff + ptr->e_shentsize * ptr->e_shstrndx));

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;
	}

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		if (strcmp(sh_name_buffer[i], section) == 0){
			offset = buffer_mdata_sh[i]->sh_offset;
			*i_sec = i;
			return offset;
		}
	}

	return -1;
}

// *=*=*=*=*=*=

Elf64_Phdr *search_fst_pt_load(Elf64_Ehdr *eh_ptr, Elf64_Phdr *ph_ptr[]) {

    for (size_t i = 0; i < eh_ptr->e_phnum; i++) {
        if (ph_ptr[i]->p_type == PT_LOAD && ph_ptr[i]->p_flags == 0x5) {
            return ph_ptr[i];
        }
    }

    return (Elf64_Phdr *)1;
}

