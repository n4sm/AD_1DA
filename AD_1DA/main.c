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

#include "include.h"

#include <capstone/capstone.h>
#include <keystone/keystone.h>

// Hésitez pas à lire mon code j'ai laissé des com' (pertinents ou pas mdr)

int main(int argc, char **argv){
    
    int argc_usage = 2;
    
    if (argc < argc_usage)
    {
        show_help(argv);
        return 0;
    }

    else if (!strcmp(argv[1], "-h"))
    {
        help(argv);
    }

    else if (argc == 4 && strcmp(argv[2], "-o") == 0)
    {
        ssize_t len_stub = 0;
        unsigned char *text_stub = init_map_and_get_stub(argv[3], &len_stub);
        add_section_ovrwrte_ep_inject_code(argv[1], ".p4cked", text_stub, len_stub);

        exit_clean(text_stub);
    }

    else if (argc == 4 && !strcmp(argv[2], "--add-code-only"))
    {
        printf("Non pris en charge !\n");
        printf("J'ai pas tout finis de réadapter à ma nouvelle conception des elf mdr\n");

        /*
        ssize_t len_stub = 0;
        unsigned char *text_stub = init_map_and_get_stub(argv[3], &len_stub);
        inject_code_ovrwrt_ep(argv[1], ".p4cked", text_stub, len_stub);

        exit_clean(text_stub);
        */
    }
    
    else if (argc == 5 && !strcmp(argv[2], "--add-code-only") && !strcmp(argv[3], "--raw-data"))
    {
        printf("Non pris en charge !\n");
        printf("J'ai pas tout finis de réadapter à ma nouvelle conception des elf mdr\n");

        /*
        ssize_t len_stub = 0;
        unsigned char *text_stub = init_map_and_get_stub_raw(argv[4], &len_stub);
        inject_code_ovrwrt_ep(argv[1], ".p4cked", text_stub, len_stub);

        exit_clean(text_stub);
        */
    }
    
    else
    {
        show_help(argv);
    }

    return 0;
}