//
// Created by nasm on 11/03/2021.
//

#ifndef AD_1DA_BINARY_H
#define AD_1DA_BINARY_H

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

// =*=*=*=*=*=*=*=*=
// Const for pattern

#define STUB_VADDR 0x3333333333333333
#define BASE_ADDR 0x3333333333333333
#define ENTRY_POINT 0x1010101010101010
#define RANDOM_KEY 0x4444444444444444
#define LEN_STUB 0x5555555555555555
#define STUB_FILE_OFFSET 0x6666666666666666
#define GARBAGE_FILE_OFFSET 0x7777777777777777
#define TEXT_FILE_OFFSET 0x1111111111111111
#define LEN_TEXT_ULONG 0x8888888888888888
#define LEN_TEXT_BYTES 0x88888888888888cc
#define LAST_PT_LOAD_OFFSET 0x9999999999999999

#include <keystone/keystone.h>
#include <capstone/capstone.h>

typedef struct mdata_binary_s {
    unsigned char *fbinary; // malloc pointer to the binary
    unsigned char *stub; // pointer to the stub lmao
    unsigned long len_stub;
    unsigned long len_file;
    const char *filename;
    int fd; // fd of the binary
    // =*=*=*=*=*=*=* // dynamic fields
    unsigned long current_layer; // counter updated each time a stub is added
    unsigned long back_target_offt; // offset of the target area
    unsigned long target_len; // length of the target area
} mdata_binary_t;

int init_binary(const char *filename, mdata_binary_t *s_binary, unsigned char *stub, ssize_t len_stub);

int free_binary(mdata_binary_t *s_binary);

int add_section_ovrwrte_ep_inject_code(mdata_binary_t  *s_binary, bool meta, int (*u_callback)(unsigned long *, ssize_t, unsigned long));

int wrapper_layer(const char *filename, const char *name_sec, unsigned char *stub, ssize_t len_stub, bool meta, ssize_t layer, int (*u_callback)(unsigned long *, ssize_t, unsigned long));

int inject_section(unsigned char *buffer_bytes, ssize_t buffer_len, unsigned char *address_to_inject, off_t from_to_inject);

unsigned char *init_map_and_get_stub(const char *stub_file, ssize_t *len_stub, bool disass_or_not);

#endif //AD_1DA_BINARY_H
