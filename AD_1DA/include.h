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

//  =====================================================================
//  =======================elf prototypes functions======================
//  =====================================================================


int is_elf(unsigned char *eh_ptr);

int add_section_ovrwrte_ep_inject_code(const char *filename, const char *name_sec, unsigned char *stub, ssize_t len_stub, bool pie, bool meta);

int inject_code_ovrwrt_ep(const char *filename, const char *name_sec, unsigned char *stub, ssize_t len_stub);

int inject_code_ovrwrt_ep_raw_data(const char *filename, const char *name_sec, unsigned char *stub, ssize_t len_stub);

unsigned char *init_map_and_get_stub(const char *stub_file, ssize_t *len_stub);

unsigned char *init_map_and_get_stub_raw(const char *stub_file, ssize_t *len_stub);

int create_new_section(const char *filename, ssize_t len_sec, const char *name_sec);

unsigned char *m_new_section(unsigned char *target_pt_load,  unsigned char *target_scnd_pt_load, Elf64_Phdr *buffer_mdata_ph[], ssize_t sz_sec, ssize_t len_target_file, ssize_t len_data);

unsigned char *m_extend_code(Elf64_Ehdr *target_pt_load,  unsigned char *target_scnd_pt_load, Elf64_Phdr *buffer_mdata_ph[], ssize_t sz_sec, ssize_t len_target_file, ssize_t len_data);

int inject_section(unsigned char *buffer_bytes, ssize_t buffer_len, unsigned char *address_to_inject, off_t from_to_inject);

Elf64_Phdr *search_fst_pt_load(Elf64_Ehdr *eh_ptr, Elf64_Phdr *ph_ptr[]);

Elf64_Shdr *elf_struct_search_section_name(Elf64_Ehdr *eh_ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section, char *sh_name_buffer[]);

int rename_target_section(Elf64_Ehdr *eh_ptr, Elf64_Phdr *buffer_mdata_ph[], Elf64_Shdr *buffer_mdata_sh[], unsigned char *file_ptr, Elf64_Shdr *target_shdr);

int rewrite_ep(Elf64_Ehdr *eh_ptr, Elf64_Phdr *buffer_mdata_ph[], Elf64_Shdr *buffer_mdata_sh[], unsigned char *address_to_inject);

ssize_t len_bytes(unsigned char *bytes);

unsigned char *craft_mprotect_memory(ssize_t *len_crafted_stub);

//int meta_patch();

// ========================== Functions from my packer and my disassembler ============================
// ==============================https://github.com/n4sm/m0dern_p4cker=================================
// ====================================================================================================

size_t len_section(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section);

off_t search_section_name(char *sh_name_buffer[], Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], const char *section, size_t *len_sec);

int patch_target(void *p_entry, long pattern, int size, long patch);

int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]);

int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]);

uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *ptr);

char  *parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char *sh_name_buffer[ptr->e_shnum]);

int x_pack_text(unsigned char *base_addr, size_t len_text, int random_int);

int r_pack_text(unsigned char *base_addr, size_t len_text, int random_int);

int c_pack_text(unsigned char *base_addr, size_t len_text, int random_int, int x);

off_t search_section(const char *section, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *ptr, int *i_sec);

int xor_encrypt(char *target_file);

int has_pie_or_not(Elf64_Phdr *buffer_mdata_ph[], Elf64_Ehdr *ptr);

int xor_encrypt_pie(char *file_ptr);

int not_encrypt(char *target_file);

int not_encrypt_pie(char *target_file);

int complexe_encrypt(char *target_file);

int rol(int in, int x);

int ror(int in, int x);

int complexe_encrypt_pie(char *target_file);

Elf64_Shdr *search_section_from_offt(off_t offset, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *file_ptr, size_t *_i__);

// ====================================================================================================
// ====================================================================================================
// ====================================================================================================

int disass_raw(unsigned char *raw_bytes, ssize_t len_raw_code);
