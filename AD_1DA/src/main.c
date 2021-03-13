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
#include <errno.h>

#include "include/parsing_utils.h"
#include "include/misc.h"
#include "include/binary.h"

#include <capstone/capstone.h>
#include <keystone/keystone.h>

// just an example of basic xor encryption, the engine is providing a 8 byte key and the length of the executable area
int x_pack_text(unsigned long *base_addr, ssize_t len_text, unsigned long random_int) {
    for (size_t i = 0; i < len_text; i++) {
        base_addr[i] ^= random_int;
    }

    return 0;
}

int main(int argc, char **argv){
    unsigned long layer = 0;
    ssize_t len_stub = 0;
    bool meta = false;

    if (argc != 5) {
        printf("Usage %s <target> (option) *stub* |layer|\n"
               "Options:\n"
               "\t-o: Injection and basic patching\n"
               "\t-m: Injection and self modification\n"
               "stub:\n"
               "\tYou can use either your stub or default stub => stub/\n"
               "layer:\n"
               "\tNumber of layer you want for the final binary (base 16)\n", argv[0]);

        return -1;
    }

    if (argv[2][0] != '-' ||
                argv[2][1] != 'm' && argv[2][1] != 'o') {
        log_ad("Bad Option\n", FAILURE);
        return -1;
    }

    char **end = 0;

    layer = strtol(argv[4], end, 16);

    if (errno != 0) {
        printf("Conversion error, %s\n", strerror(errno));
    } else if (layer < 0) {
        log_ad("Bad layer\n", FAILURE);
        return -1;
    }

    if ((char)argv[2][1] == 'm') {
        meta = true;
    }

    unsigned char *stub = NULL;
    if (!(stub = init_map_and_get_stub(argv[3], &len_stub, true)))
        return -1;

    wrapper_layer(argv[1], ".x", stub, len_stub, meta, layer, x_pack_text);

    free(stub);

    return 0;
}