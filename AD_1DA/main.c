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
#include "misc.h"

#include <capstone/capstone.h>
#include <keystone/keystone.h>

// Hésitez pas à lire mon code j'ai laissé des com' (pertinents ou pas mdr)

int main(int argc, char **argv){
    
    greetz();

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
        add_section_ovrwrte_ep_inject_code(argv[1], ".p4cked", text_stub, len_stub, false, false);

        exit_clean(text_stub);
    }

    else if (argc == 5 && !strcmp(argv[2], "-o") && !strcmp(argv[4], "-pie"))
    {
        ssize_t len_stub = 0;
        unsigned char *text_stub = init_map_and_get_stub(argv[3], &len_stub);

        add_section_ovrwrte_ep_inject_code(argv[1], ".p4cked", text_stub, len_stub, true, false);

        exit_clean(text_stub);
    }
    

    else if (argc == 5 && !strcmp(argv[2], "-m") && !strcmp(argv[4], "-pie"))
    {
        ssize_t len_stub = 0;
        unsigned char *text_stub = init_map_and_get_stub(argv[3], &len_stub);

        add_section_ovrwrte_ep_inject_code(argv[1], ".p4cked", text_stub, len_stub, true, true);

        exit_clean(text_stub);
    }

    else if (argc == 4 && !strcmp(argv[2], "-m"))
    {
        ssize_t len_stub = 0;
        unsigned char *text_stub = init_map_and_get_stub(argv[3], &len_stub);

        add_section_ovrwrte_ep_inject_code(argv[1], ".p4cked", text_stub, len_stub, false, true);

        exit_clean(text_stub);
    }
    

    else
    {
        show_help(argv);
    }

    return 0;
}