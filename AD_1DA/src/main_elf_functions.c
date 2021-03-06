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
#include <pthread.h>

#include "include/parsing_utils.h"
#include "include/misc.h"
#include "include/binary.h"

#include <keystone/keystone.h>
#include <capstone/capstone.h>

/*
 Dieu et le Roy.
*/

// is elf ?
int is_elf(unsigned char *eh_ptr) {
    if ((unsigned char)eh_ptr[EI_MAG0] != 0x7F ||
        (unsigned char)eh_ptr[EI_MAG1] != 'E' ||
        (unsigned char)eh_ptr[EI_MAG2] != 'L' || 
        (unsigned char)eh_ptr[EI_MAG3] != 'F') {
        return -1;
    }

    return 0;
}

// Wrapper to the core
int wrapper_layer(const char *filename,
                  const char *name_sec,
                  unsigned char *stub,
                  ssize_t len_stub,
                  bool meta,
                  ssize_t layer,
                  int (*u_callback)(unsigned long *, ssize_t, unsigned long)) {
    unsigned char *fresh_stub = malloc(len_stub);
    mdata_binary_t *s_binary = malloc(sizeof(mdata_binary_t));

    if (init_binary(filename, s_binary, fresh_stub, len_stub)) {
        log_ad("Exit\n", FAILURE);
        exit(-1);
    }

    log_ad("Working on: ", SUCCESS);
    printf("%s\n", filename);

    for (int i = 0; i < layer; ++i) {
       printf("Working on layer 0x%x => %s\n", i, filename);
       memcpy(fresh_stub, stub, len_stub);
       // Reset fresh stub for each iteration

       if (add_section_ovrwrte_ep_inject_code(s_binary, meta, u_callback) == -1) {
           free(fresh_stub);
           free(s_binary);

           log_ad("Exit\n", FAILURE);
           exit(-1);
       }

       s_binary->current_layer += 1;

    }

    const char *new_name = (const char *)strcat((char *)filename, name_sec);
    dump_file(new_name, s_binary->fbinary, s_binary->len_file);

    free_binary(s_binary);
    free(s_binary);

    return 0;
}

// *=*=*=*=*=*=*=*

// core
int add_section_ovrwrte_ep_inject_code(mdata_binary_t  *s_binary,
                                       bool meta,
                                       int (*u_callback)(unsigned long *, ssize_t, unsigned long)) {
    unsigned char *file_ptr;
    unsigned long random_key = 0;
    ssize_t len_text_runtime = 0;
    ssize_t len_text = 0;
    unsigned long ep;
    off_t offt_text_ifile = 0x0;

    // Elf structure

    Elf64_Ehdr *eh_ptr = (Elf64_Ehdr *)s_binary->fbinary;
    
    Elf64_Phdr *buffer_mdata_ph[eh_ptr->e_phnum];
    Elf64_Shdr *buffer_mdata_sh[eh_ptr->e_shnum];
    //char *sh_name_buffer[eh_ptr->e_shnum];

    // parsing
    parse_shdr(eh_ptr, buffer_mdata_sh);
    parse_phdr(eh_ptr, buffer_mdata_ph);

    off_t offset = 0;

    // *=*=*=*=*=*=*=*

    Elf64_Phdr *last_pt_load = NULL;
    Elf64_Phdr *pt_dyn = NULL;
    Elf64_Phdr *garbage_pt_load = NULL;
    ssize_t gap_garbage = 0;

    bool pie = is_pie(buffer_mdata_ph, eh_ptr);

    unsigned long base_addr = search_base_addr(buffer_mdata_ph, eh_ptr);

    // We are looking for the last PT_LOAD segment
    for (size_t i = 0; i < eh_ptr->e_phnum; i++) {
        if (buffer_mdata_ph[i]->p_type == PT_LOAD) {
            if (i) {
                garbage_pt_load = buffer_mdata_ph[i-1];
            }

            last_pt_load = buffer_mdata_ph[i];
        } else if (buffer_mdata_ph[i]->p_type == PT_DYNAMIC) {
            pt_dyn = buffer_mdata_ph[i];

            log_ad("PT_DYN:\n", SUCCESS);
            dump_struct(pt_dyn, Elf64_PHDR);
        }
    }

    if (!garbage_pt_load) {
        log_ad("AD_1DA does not support binary with only one PT_LOAD for now\n", FAILURE);
        log_ad("Please do a PR at: https://github.com/n4sm/AD_1DA/pulls if you can change that >.<\n", FAILURE);
        return -1;
    }

    log_ad("garbage PT_LOAD:\n", SUCCESS);
    dump_struct(garbage_pt_load, Elf64_PHDR);

    log_ad("last PT_LOAD:\n", SUCCESS);
    dump_struct(last_pt_load, Elf64_PHDR);

    if (!last_pt_load) {
        log_ad("PT_LOAD not found\n", FAILURE);
        log_ad("Exit ..\n", FAILURE);

        return -1;
    }

    // We malloc the final binary

    ssize_t offt_stub = last_pt_load->p_offset + last_pt_load->p_filesz; // offset to take car about the gap between memsz & filesz
    ssize_t offt_stub_runtime = last_pt_load->p_offset + last_pt_load->p_memsz; // runtime offset to take care about the gap between memsz & filesz
    ssize_t end_pt_load = offt_stub;

    ssize_t gap = offt_stub_runtime - offt_stub;

    log_ad("gap between last_pt_load and the stub: ", SUCCESS);
    printf("0x%lx\n", gap);

    // offset of the .text
    // If it's the first time we're working on the binary
    if (!s_binary->current_layer) {
       offt_text_ifile = search_x_segment_ifile(buffer_mdata_ph, eh_ptr, (int *)&len_text);
       s_binary->back_target_offt = offt_text_ifile;
       s_binary->target_len = len_text;
    } else {
        len_text = s_binary->target_len;
        offt_text_ifile = s_binary->back_target_offt;
    }

    log_ad("Target executable memory area offt: ", SUCCESS);
    printf("0x%lx (file)\n", offt_text_ifile);

    log_ad("Length of the target executable area: ", SUCCESS);
    printf("0x%lx\n", s_binary->target_len);

    if (meta) {
        unsigned long tmp[0x100];
        int fd_rand = open("/dev/urandom", O_RDONLY);

        if (fd_rand < 0) {
            log_ad("Fatal fd_rand\n", FAILURE);
            return -1;
        }

        read(fd_rand, tmp, 0x100*sizeof(unsigned long));
        random_key = tmp[0x50] & 0xffffffffffffffff;

        close(fd_rand);
    }

    // Pie or not
    if (pie) {
        // Either the pie or not, so we patch the stub with few values

        log_ad("The binary PIE based!\n", SUCCESS);

        if (patch_target(s_binary->stub,
                         STUB_VADDR, // vaddr of the beg of the stub in the file
                         s_binary->len_stub,
                         (unsigned long)(last_pt_load->p_vaddr + last_pt_load->p_memsz)) ||
            patch_target(s_binary->stub,
                         ENTRY_POINT, // entry point
                         s_binary->len_stub,
                         (unsigned long)(eh_ptr->e_entry))) {
            return -1;
        }

        log_ad("Virtual address of the stub: ", SUCCESS);
        printf("0x%lx\n", (last_pt_load->p_vaddr + last_pt_load->p_memsz));

        // overwrite l'ep

        unsigned long back_ep = eh_ptr->e_entry;

        eh_ptr->e_entry = last_pt_load->p_vaddr + last_pt_load->p_memsz; // Vu que là on est au niveau de la mémoire, on manipule l'addr virtuelle et sa memoty size
        log_ad("Entry point patched: ", SUCCESS);
        printf("0x%lx => 0x%lx\n", back_ep, eh_ptr->e_entry);

        // Check if the binary will be metamorphic

        if (meta) {
            // 1. Patch the stub with specials patterns

            log_ad("Code cave length: ", SUCCESS);
            printf("0x%lx\n", last_pt_load->p_offset - (garbage_pt_load->p_filesz + garbage_pt_load->p_offset));

            if (patch_target(s_binary->stub,
                             (unsigned long)RANDOM_KEY, // random key
                             s_binary->len_stub,
                             (unsigned long)random_key) ||
                patch_target(s_binary->stub,
                             (unsigned long)LEN_STUB, // stub length
                             s_binary->len_stub,
                             s_binary->len_stub) ||
                patch_target(s_binary->stub,
                             (unsigned long)STUB_FILE_OFFSET, // offset (not at runtime) in the binary
                             s_binary->len_stub,
                             (unsigned long)last_pt_load->p_offset + last_pt_load->p_filesz + gap) ||
                patch_target(s_binary->stub,
                             (unsigned long)GARBAGE_FILE_OFFSET,
                             s_binary->len_stub,
                             (unsigned long)garbage_pt_load->p_offset + garbage_pt_load->p_filesz) || // beg of the garbage bytes
                patch_target(s_binary->stub,
                             (unsigned long)TEXT_FILE_OFFSET, // offset executable area
                             s_binary->len_stub,
                             (unsigned long)offt_text_ifile) ||
                patch_target(s_binary->stub,
                             (unsigned long)LEN_TEXT_ULONG,
                             s_binary->len_stub,
                             (unsigned long)len_text / 8) || // length exec area
                patch_target(s_binary->stub,
                             (unsigned long)LEN_TEXT_BYTES, // special pattern for text length in bytes
                             s_binary->len_stub,
                             (unsigned long)len_text) || // NON runtime length
                patch_target(s_binary->stub,
                             (unsigned long)LAST_PT_LOAD_OFFSET, // virtual last PT_LOAD offt
                             s_binary->len_stub,
                             (unsigned long)last_pt_load->p_offset) == -1) {
                printf("The stub cannot be patched because some pattern cannot be found\n");
                return -1;
            }
        }
    } else {
        // Search the base address

        unsigned long back_ep = eh_ptr->e_entry;

        if (!base_addr) {
            log_ad("Binary not PIE based\n", FAILURE);
            return -1;
        }

        eh_ptr->e_entry = last_pt_load->p_vaddr + last_pt_load->p_memsz;
        log_ad("The base address of the target binary is: ", SUCCESS);
        printf("0x%lx\n", base_addr);

        log_ad("Entry point patched: ", SUCCESS);
        printf("0x%lx => 0x%lx\n", back_ep, eh_ptr->e_entry);

        if (patch_target(s_binary->stub,
                         (unsigned long )BASE_ADDR,
                         s_binary->len_stub,
                         (unsigned long)base_addr)) {
            log_ad("The stub cannot be patched because the pattern 0x3333333333333333 can't be found\n", FAILURE); // 0x3333333333333333
            return -1;
        }

        if (meta) {
            log_ad("Code cave length : ", SUCCESS);
            printf("0x%lx\n", last_pt_load->p_offset - (garbage_pt_load->p_offset + garbage_pt_load->p_filesz));

            if (patch_target(s_binary->stub,
                             (unsigned long)RANDOM_KEY,
                             s_binary->len_stub,
                             (unsigned long)random_key) ||
                patch_target(s_binary->stub,
                             (unsigned long)LEN_STUB,
                             s_binary->len_stub,
                             (unsigned long)s_binary->len_stub) ||
                patch_target(s_binary->stub,
                             (unsigned long)STUB_FILE_OFFSET, // NON virtual offt in the stub
                             s_binary->len_stub,
                             (unsigned long)last_pt_load->p_offset + last_pt_load->p_memsz) ||
                patch_target(s_binary->stub,
                             (unsigned long)GARBAGE_FILE_OFFSET, // beg garbage bytes
                             s_binary->len_stub,
                             (unsigned long)garbage_pt_load->p_filesz + garbage_pt_load->p_offset) ||
                patch_target(s_binary->stub,
                             (unsigned long)TEXT_FILE_OFFSET,
                             s_binary->len_stub,
                             (unsigned long)offt_text_ifile) || // NON virtual offt
                patch_target(s_binary->stub,
                             (unsigned long)LEN_TEXT_ULONG,
                             s_binary->len_stub,
                             (unsigned long)len_text / 8) || // NON runtime length
                patch_target(s_binary->stub,
                             (unsigned long)LEN_TEXT_BYTES, // special pattern for text length in bytes
                             s_binary->len_stub,
                             (unsigned long)len_text) || // NON runtime length
                patch_target(s_binary->stub,
                             (unsigned long)ENTRY_POINT,
                             s_binary->len_stub,
                             (unsigned long)back_ep) || // virtual offt ep
                patch_target(s_binary->stub,
                             (unsigned long)LAST_PT_LOAD_OFFSET, // offset last PT_LOAD
                             s_binary->len_stub,
                             (unsigned long)last_pt_load->p_offset)) { // offset NOT at runtime
                return -1;
            }
        }
    }

    // edit program header
    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_ph[i]->p_offset > offt_stub_runtime) {
            buffer_mdata_ph[i]->p_offset += s_binary->len_stub;
            buffer_mdata_ph[i]->p_paddr += s_binary->len_stub;
            buffer_mdata_ph[i]->p_vaddr += s_binary->len_stub;
        }
    }

    last_pt_load->p_filesz += gap + s_binary->len_stub;
    last_pt_load->p_memsz += s_binary->len_stub;

    last_pt_load->p_flags |= PF_X;

    eh_ptr->e_shoff = 0x0; // edit section header table offset
    eh_ptr->e_shnum = 0x0;
    eh_ptr->e_shentsize = 0x0;
    eh_ptr->e_shstrndx = 0x0;

    // put all together

    unsigned char *local_fbinary = mmap(NULL,
                                        offt_stub_runtime + s_binary->len_stub,
                                        PROT_READ | PROT_WRITE,
                                        MAP_ANONYMOUS | MAP_PRIVATE,
                                        -1,
                                        0x0);

    memset(local_fbinary, 0x0, offt_stub_runtime + s_binary->len_stub);

    memcpy(local_fbinary,
            s_binary->fbinary,
            offt_stub); // All data back the stub

    memcpy(local_fbinary
                + offt_stub_runtime,
            s_binary->stub,
            s_binary->len_stub); // The stub itself

    s_binary->len_file = offt_stub_runtime + s_binary->len_stub;

    unsigned char *tmp = NULL;
    if (!(tmp = realloc(s_binary->fbinary, s_binary->len_file) )) {
        free(s_binary->fbinary);
        log_ad("Fatal realloc\n", FAILURE);
        return -1;
    }

    s_binary->fbinary = tmp;

    memcpy(s_binary->fbinary, local_fbinary, s_binary->len_file);

    if (meta) {
        u_callback((unsigned long *)(s_binary->fbinary + offt_text_ifile), len_text / 8, random_key);
    }

    log_ad("Bytes injected at ", SUCCESS);
    printf("0x%lx:\n\t", offt_stub + gap);

    for (size_t i = 0; i < s_binary->len_stub; i++) {
        printf("%x", *(s_binary->fbinary + offt_stub_runtime + i));
    }

    printf("\n");

    log_ad("Stub length: ", SUCCESS);
    printf("0x%lx\n", s_binary->len_stub);

    if (munmap(local_fbinary, s_binary->len_file) == -1) {
        log_ad("Error munmap\n", FAILURE);
        return -1;
    }

    return 0;
}

// *=*=*=*=*=*=*=*

// return valid pointer to the executable bytes of the stub if success and NULL if error
unsigned char *init_map_and_get_stub(const char *stub_filename, ssize_t *len_stub, bool disass_or_not) {
    struct stat stat_file = {0};

    int fd = open(stub_filename, O_RDWR);

    if (fd < 0) {
        log_ad("Error open: ", FAILURE);
        printf("%s\n", stub_filename);
    }

    if (fstat(fd, &stat_file)) {
        printf("[ERROR] fstat has failed\n");
        return NULL;
    }

    unsigned char *stub_ptr = mmap(0, stat_file.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

    *len_stub = stat_file.st_size;

    if (stub_ptr == MAP_FAILED) {
        printf("[ERROR] mmap has failed\n");
        return NULL;
    }

    Elf64_Ehdr *eh_ptr = (Elf64_Ehdr *)stub_ptr;

    Elf64_Phdr *buffer_mdata_ph[eh_ptr->e_phnum];
    Elf64_Shdr *buffer_mdata_sh[eh_ptr->e_shnum];

    parse_shdr(eh_ptr, buffer_mdata_sh);
    parse_phdr(eh_ptr, buffer_mdata_ph);

    char *sh_name_buffer[eh_ptr->e_shnum];
	Elf64_Shdr *shstrtab_header = (Elf64_Shdr *)((char *)stub_ptr + eh_ptr->e_shoff + eh_ptr->e_shentsize * eh_ptr->e_shstrndx);

    off_t offset = 0;

    const char *shstrndx = (const char *)stub_ptr + shstrtab_header->sh_offset;

    for (size_t i = 0; i < eh_ptr->e_shnum; i++) {
		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;
	}

    // *=*=*=*=*=*=*=*

    // Search base_address

    off_t offset_entry = 0;

    if (!is_pie(buffer_mdata_ph, eh_ptr)) {
        offset_entry = eh_ptr->e_entry; // pie
    } else {
        uint64_t base_address = search_base_addr(buffer_mdata_ph, eh_ptr);
        offset_entry = eh_ptr->e_entry - base_address;
    }

    // *=*=*=*=*=*=*=*

    off_t offset_text = search_section_name(sh_name_buffer, eh_ptr, buffer_mdata_sh, ".text", len_stub);

    int size_stub_malloc = *len_stub;

    unsigned char *text_stub = malloc(size_stub_malloc);

    memcpy(text_stub, stub_ptr + offset_text, size_stub_malloc);

    printf("Raw executables bytes in the stub : \n");
    printf("\t");

    for (size_t i = 0; i < size_stub_malloc; i++) {
        printf("%x", *(text_stub + i));
    }

    printf("\n");

    if (disass_or_not) {
        printf("Disassembling the stub : \n");

        disass_raw(text_stub, size_stub_malloc); // Disassembly
    }

    if (munmap(stub_ptr, stat_file.st_size)) {
       return NULL;
    }

    close(fd);

    return text_stub;
}

// *=*=*=*=*=*=*=*

int init_binary(const char *filename, mdata_binary_t *s_binary, unsigned char *stub, ssize_t len_stub) {
    struct stat st;

    memset(s_binary, 0x0, sizeof(mdata_binary_t));

    if ((s_binary->fd = open(filename, O_RDWR)) == -1) {
        log_ad("[ERROR] Open: ", FAILURE);
        printf("%s: \n", filename);
        return -1;
    }

    if (fstat(s_binary->fd, &st)) {
        printf("[ERROR] fstat has failed1\n");
        return -1;
    }

    s_binary->len_file = st.st_size;
    s_binary->fbinary = (unsigned char *)malloc(s_binary->len_file);
    read(s_binary->fd, s_binary->fbinary, s_binary->len_file);

    if (s_binary->fbinary == MAP_FAILED) {
        printf("[ERROR] mmap has failed\n");
        return -1;
    }

    s_binary->stub = stub;
    s_binary->len_stub = len_stub;
    s_binary->filename = filename;
    s_binary->current_layer = 0x0;
    s_binary->back_target_offt = 0x0;
    s_binary->target_len = 0x0;

    return 0;
}

int free_binary(mdata_binary_t *s_binary) {
    close(s_binary->fd);
    free(s_binary->stub);
    free(s_binary->fbinary);

    return 0;
}


