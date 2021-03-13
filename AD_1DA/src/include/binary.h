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

#include <keystone/keystone.h>
#include <capstone/capstone.h>

typedef struct mdata_binary_s {
    unsigned char *fbinary;
    unsigned char *stub;
    unsigned long len_stub;
    unsigned long len_file;
    const char *filename;
    int fd;
} mdata_binary_t;

int init_binary(const char *filename, mdata_binary_t *s_binary, unsigned char *stub, ssize_t len_stub);

int free_binary(mdata_binary_t *s_binary);

#endif //AD_1DA_BINARY_H
