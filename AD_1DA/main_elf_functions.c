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

/*

    Bon on réfléchit, 

    On a :

    // --------------------------// |
                                    |
    //        Elf Header         // |
                                    |
    // --------------------------// |
                                    |
    //    Program Header Table   // | =========> 1er PT_LOAD
                                    |
    // --------------------------// |
                                    |
    //       Nos sections        // | --------------------------------
                                    |
    // --------------------------// | ========> 2eme PT_LOAD

    //    Section header table   //

    // --------------------------//


*/

// ========================== Check if the file is an elf ============================

int is_elf(unsigned char *eh_ptr){

    if ((unsigned char)eh_ptr[EI_MAG0] != 0x7F ||
        (unsigned char)eh_ptr[EI_MAG1] != 'E' ||
        (unsigned char)eh_ptr[EI_MAG2] != 'L' || 
        (unsigned char)eh_ptr[EI_MAG3] != 'F'){
        return -1;
    }

    return 0;
}

// ========================== New main function ============================

int add_section_ovrwrte_ep_inject_code(const char *filename, const char *name_sec, unsigned char *stub, ssize_t len_stub){

    struct stat stat_file = {0};
    unsigned char *file_ptr;
    int fd=0;

    // Elf structure

    Elf64_Ehdr *eh_ptr = NULL;
    
    // ====

    if ((fd = open(filename, O_RDWR)) == -1)
    {
        perror("[ERROR] Open\n");
        return -1;
    }

    // ====

    if (fstat(fd, &stat_file))
    {
        printf("[ERROR] fstat has failed1\n");
        return -1;
    }


    file_ptr = (unsigned char *)mmap(0, stat_file.st_size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    
    if (file_ptr == MAP_FAILED)
    {
        printf("[ERROR] mmap has failed\n");
        return 1;
    }



    // Initialisation et mise en place des différentes structures

    eh_ptr = (Elf64_Ehdr *)file_ptr;

    Elf64_Phdr *buffer_mdata_ph[eh_ptr->e_phnum];
    Elf64_Shdr *buffer_mdata_sh[eh_ptr->e_shnum];

    parse_shdr(eh_ptr, buffer_mdata_sh);
    parse_phdr(eh_ptr, buffer_mdata_ph);

    char *sh_name_buffer[eh_ptr->e_shnum];
    
    off_t offset = 0;
	Elf64_Shdr *shstrtab_header;

    shstrtab_header = (Elf64_Shdr *)((char *)file_ptr + eh_ptr->e_shoff + eh_ptr->e_shentsize * eh_ptr->e_shstrndx);

    char *shstrndx = (char *)file_ptr + shstrtab_header->sh_offset;

    for (size_t i = 0; i < eh_ptr->e_shnum; i++){

		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;

	}

    // ==========

    Elf64_Phdr *phdr_fst_pt_load = search_fst_pt_load(eh_ptr, buffer_mdata_ph);

    unsigned char *fst_pt_load = malloc(eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz);

    memcpy(fst_pt_load, file_ptr + phdr_fst_pt_load->p_offset, eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz);

    // ==========

    ssize_t len_data = eh_ptr->e_shoff - (eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz); // En vrai la taille change pas l'offset va changer par contre

    Elf64_Shdr *sh_h_table_malloc = malloc(eh_ptr->e_shnum * sizeof(Elf64_Shdr) + len_data);

    memcpy(sh_h_table_malloc, file_ptr + eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz, stat_file.st_size - (eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz));

    // ==========

    unsigned char *address_to_inject =  m_new_section((Elf64_Ehdr *)fst_pt_load, (unsigned char *)sh_h_table_malloc, buffer_mdata_ph, len_stub, stat_file.st_size, len_data);

    if (inject_section(stub, len_stub, address_to_inject, phdr_fst_pt_load, eh_ptr))
    {
        perror("[ERROR] Exit \n");
        return -1;
    }

    rewrite_ep(eh_ptr, buffer_mdata_ph, buffer_mdata_sh, address_to_inject);

    rename_target_section(eh_ptr, buffer_mdata_ph, buffer_mdata_sh, address_to_inject, 0);

    // memset(address_to_inject + eh_ptr->e_ehsize + (eh_ptr->e_phnum * eh_ptr->e_phentsize) + phdr_fst_pt_load->p_filesz, 0xcc, len_stub);
    
    char *name_file_dumped = strcat((char *)filename, ".p4cked");

    printf("[*] Generating a new %s executable file\n", name_file_dumped);

    int file_dumped = open(name_file_dumped,  O_RDWR | O_CREAT, 0777);

    if (file_dumped == -1)
    {
        perror("[ERROR] open\n");
        close(file_dumped);
    }
    
    write(file_dumped, address_to_inject, stat_file.st_size + sizeof(Elf64_Shdr) + len_stub);

    printf("Bytes injected : \n");
    printf("\t");

    for (size_t i = 0; i < len_stub; i++)
    {
        printf("%x", *(address_to_inject + eh_ptr->e_ehsize + (eh_ptr->e_phnum * eh_ptr->e_phentsize) + phdr_fst_pt_load->p_filesz + i));
    }
    
    printf("\n");

    printf("Length of the stub : 0x%lx\n", len_stub);


    /*
    if (stat_file.st_size == eh_ptr->e_ehsize + (eh_ptr->e_phnum * eh_ptr->e_phentsize) + phdr_fst_pt_load->p_filesz + len_data + eh_ptr->e_shnum * eh_ptr->e_shentsize)
    {
        printf("COOOOl %d == %d\n", stat_file.st_size, eh_ptr->e_ehsize + (eh_ptr->e_phnum * eh_ptr->e_phentsize) + phdr_fst_pt_load->p_filesz + len_data + eh_ptr->e_shnum * eh_ptr->e_shentsize);
    }
    */


    // =====

    if (munmap(file_ptr, stat_file.st_size) != 0){
		exit(-1);
	}

    // On close et on déalloue, car oe il est hq notre prog

    close(fd);
    close(file_dumped);

    free(sh_h_table_malloc);
    free(fst_pt_load);
    free(address_to_inject);

    return 0;
}

// ===========================================================================================================


unsigned char *init_map_and_get_stub(const char *stub_file, ssize_t *len_stub){

    struct stat stat_file = {0};

    int fd = open(stub_file, O_RDWR);

    if (fstat(fd, &stat_file))
    {
        printf("[ERROR] fstat has failed\n");
        return NULL;
    }

    unsigned char *stub_ptr = mmap(0, stat_file.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if (stub_ptr == MAP_FAILED)
    {
        printf("[ERROR] mmap has failed\n");
        return NULL;
    }

    Elf64_Ehdr *eh_ptr = (Elf64_Ehdr *)stub_ptr;

    Elf64_Phdr *buffer_mdata_ph[eh_ptr->e_phnum];
    Elf64_Shdr *buffer_mdata_sh[eh_ptr->e_shnum];

    parse_shdr(eh_ptr, buffer_mdata_sh);
    parse_phdr(eh_ptr, buffer_mdata_ph);

    char *sh_name_buffer[eh_ptr->e_shnum];
    
    off_t offset = 0;
	Elf64_Shdr *shstrtab_header;

    shstrtab_header = (Elf64_Shdr *)((char *)stub_ptr + eh_ptr->e_shoff + eh_ptr->e_shentsize * eh_ptr->e_shstrndx);

    const char *shstrndx = (const char *)stub_ptr + shstrtab_header->sh_offset;

    for (size_t i = 0; i < eh_ptr->e_shnum; i++){

		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;

	}

    off_t offset_entry = 0;

    if (!has_pie_or_not(buffer_mdata_ph, eh_ptr))
    {
        offset_entry = eh_ptr->e_entry; // a le pie
    }
    else
    {
        uint64_t base_address = search_base_addr(buffer_mdata_ph, eh_ptr);
        offset_entry = eh_ptr->e_entry - base_address;
    }
    

    off_t offset_text = search_section_name(sh_name_buffer, eh_ptr, buffer_mdata_sh, ".text", len_stub);
    
    //= elf_struct_search_section_name(eh_ptr, buffer_mdata_sh, ".text", sh_name_buffer);

    int size_stub_malloc = *len_stub;

    unsigned char *text_stub = malloc(size_stub_malloc);

    memcpy(text_stub, stub_ptr + offset_text, size_stub_malloc);

    printf("Raw executables bytes in the stub : \n");
    printf("\t");

    for (size_t i = 0; i < size_stub_malloc; i++)
    {
        printf("%x", *(text_stub + i));
    }

    printf("\n");

    printf("Disassembling the stub : \n");

    disass_raw(text_stub, size_stub_malloc);

    if (munmap(stub_ptr, stat_file.st_size))
    {
        exit(-1);
    }

    close(fd);

    return text_stub;
}

// ===========================================================================================================

unsigned char *init_map_and_get_stub_raw(const char *stub_file, ssize_t *len_stub){

    struct stat stat_file = {0};

    int fd = open(stub_file, O_RDWR);

    if (fstat(fd, &stat_file))
    {
        printf("[ERROR] fstat has failed\n");
        return NULL;
    }

    unsigned char *stub_ptr = mmap(0, stat_file.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if (stub_ptr == MAP_FAILED)
    {
        printf("[ERROR] mmap has failed\n");
        return NULL;
    }

    *len_stub = stat_file.st_size;

    off_t offset = 0;
    off_t offset_entry = 0;

    int size_stub_malloc = *len_stub;

    unsigned char *text_stub = malloc(size_stub_malloc);

    memcpy(text_stub, stub_ptr, size_stub_malloc);

    printf("Instructions to inject : \n");
    printf("\t");

    for (size_t i = 0; i < size_stub_malloc; i++)
    {
        printf("%c", *(text_stub + i));
    }

    printf("Instructions compiled : \n");
    printf("\t\t");

    ks_engine *ks;
    ks_err error;
    size_t count;
    unsigned char *encode;
    size_t size;

    if((error = ks_open(KS_ARCH_X86, KS_MODE_64, &ks)) != KS_ERR_OK){
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (ks_asm(ks, stub_ptr, 0, &encode, &size, &count) != KS_ERR_OK)
    {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
    }
    else
    {
        for (size_t i = 0; i < size; i++)
        {
            printf("%2x", encode[i]);
        }
        
    }

    printf("\n");

    if (munmap(stub_ptr, stat_file.st_size))
    {
        exit(-1);
    }

    ks_free(encode);
    ks_close(ks);

    close(fd);

    return text_stub;
}

// ===========================================================================================================

int main_fetcher(void){


}

// ===========================================================================================================

Elf64_Shdr *elf_struct_search_section_name(Elf64_Ehdr *eh_ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section, char *sh_name_buffer[]){

    for (size_t i = 0; i < eh_ptr->e_shnum; i++)
    {
        if (!strcmp(section, sh_name_buffer[i]))
        {
            return buffer_mdata_sh[i];
        }
        
    }

    return (Elf64_Shdr *)-1;
}

// ==============================================================================================================

int disass_raw(unsigned char *raw_bytes, ssize_t len_raw_code){

    csh handle;
    cs_insn *instruction;
    ssize_t count_insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        return -1;
    }

    count_insn = cs_disasm(handle, raw_bytes, len_raw_code, 0x0, 0x0, &instruction);

    if (count_insn > 0)
    {
        for (size_t i = 0; i < count_insn; i++)
        {
            if (*instruction[i].op_str == '\0')
            {
                printf("\t[%s]      _\n", instruction[i].mnemonic);
            }
            else
            {
                printf("\t[%s]      %s\n", instruction[i].mnemonic, instruction[i].op_str);
            }
        }
        
        cs_free(instruction, count_insn);
    }

    cs_close(&handle);

    return 0;
}

// =====================================================================================================================================

int inject_code_ovrwrt_ep(const char *filename, const char *name_sec, unsigned char *stub, ssize_t len_stub){

    struct stat stat_file = {0};
    unsigned char *file_ptr;
    int fd=0;

    // Elf structure

    Elf64_Ehdr *eh_ptr = NULL;
    
    // ====

    if ((fd = open(filename, O_RDWR)) == -1)
    {
        perror("[ERROR] Open\n");
        return -1;
    }

    // ====

    if (fstat(fd, &stat_file))
    {
        printf("[ERROR] fstat has failed1\n");
        return -1;
    }


    file_ptr = (unsigned char *)mmap(0, stat_file.st_size, PROT_WRITE | PROT_READ, MAP_SHARED, fd, 0);
    
    if (file_ptr == MAP_FAILED)
    {
        printf("[ERROR] mmap has failed\n");
        return 1;
    }



    // Initialisation et mise en place des différentes structures

    eh_ptr = (Elf64_Ehdr *)file_ptr;

    Elf64_Phdr *buffer_mdata_ph[eh_ptr->e_phnum];
    Elf64_Shdr *buffer_mdata_sh[eh_ptr->e_shnum];

    parse_shdr(eh_ptr, buffer_mdata_sh);
    parse_phdr(eh_ptr, buffer_mdata_ph);

    char *sh_name_buffer[eh_ptr->e_shnum];
    
    off_t offset = 0;
	Elf64_Shdr *shstrtab_header;

    shstrtab_header = (Elf64_Shdr *)((char *)file_ptr + eh_ptr->e_shoff + eh_ptr->e_shentsize * eh_ptr->e_shstrndx);

    char *shstrndx = (char *)file_ptr + shstrtab_header->sh_offset;

    for (size_t i = 0; i < eh_ptr->e_shnum; i++){

		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;

	}

    // ==========

    Elf64_Phdr *phdr_fst_pt_load = search_fst_pt_load(eh_ptr, buffer_mdata_ph);

    unsigned char *fst_pt_load = malloc(eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz);

    memcpy(fst_pt_load, file_ptr + phdr_fst_pt_load->p_offset, eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz);

    // ==========

    int len_reste_du_bin = stat_file.st_size - (eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_filesz);

    // ==========

    unsigned char *address_to_inject =  m_extend_code((Elf64_Ehdr *)fst_pt_load, (unsigned char *)(file_ptr + eh_ptr->e_ehsize + eh_ptr->e_phnum * eh_ptr->e_phentsize + phdr_fst_pt_load->p_offset + phdr_fst_pt_load->p_filesz), buffer_mdata_ph, len_stub, stat_file.st_size, len_reste_du_bin);

    if (inject_section(stub, len_stub, address_to_inject, phdr_fst_pt_load, eh_ptr))
    {
        perror("[ERROR] Exit \n");
        return -1;
    }

    rewrite_ep(eh_ptr, buffer_mdata_ph, buffer_mdata_sh, address_to_inject);

    rename_target_section(eh_ptr, buffer_mdata_ph, buffer_mdata_sh, address_to_inject, 0);

    // memset(address_to_inject + eh_ptr->e_ehsize + (eh_ptr->e_phnum * eh_ptr->e_phentsize) + phdr_fst_pt_load->p_filesz, 0xcc, len_stub);
    
    char *name_file_dumped = strcat((char *)filename, ".p4cked");

    printf("[*] Generating a new %s executable file\n", name_file_dumped);

    int file_dumped = open(name_file_dumped,  O_RDWR | O_CREAT, 0777);

    if (file_dumped == -1)
    {
        perror("[ERROR] open\n");
        close(file_dumped);
    }

    write(file_dumped, address_to_inject, stat_file.st_size + len_stub);

    printf("Bytes injected : \n");
    printf("\t");

    for (size_t i = 0; i < len_stub; i++)
    {
        printf("%x", *(address_to_inject + eh_ptr->e_ehsize + (eh_ptr->e_phnum * eh_ptr->e_phentsize) + phdr_fst_pt_load->p_filesz + i));
    }

    printf("\n");

    printf("Length of the stub : 0x%lx\n", len_stub);

    // =====

    if (munmap(file_ptr, stat_file.st_size) != 0){
		exit(-1);
	}

    // On close et on déalloue, car oe il est hq notre prog

    close(fd);
    close(file_dumped);

    free(fst_pt_load);
    free(address_to_inject);

    return 0;
}

// ====================================================================================================================================

int inject_code_ovrwrt_ep_raw_data(const char *filename, const char *name_sec, unsigned char *stub, ssize_t len_stub){


    return 0;
}