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

void show_help(char **argv){
    printf("Usage : %s <target_file> <option> <stub_to_inject>\n", argv[0]);
    printf("Help : %s -h\n", argv[0]);
}

void help(char **argv){
    printf("AD_1DA is a modern tool made in order to obfuscate your elf binaries\n");
    printf("Help : \n");
    printf("\t\t%s -h : Show this help\n", argv[0]);
    printf("\t\t%s <target_binary> -o <stub to inject>: Basic obfuscation\n", argv[0]);
    printf("\t\t%s <target_binary> --add-code-only <stub_to inject>: Add only the executable bytes at the end of the pt_load\n", argv[0]);
    printf("\t\t%s <target_binary> --add-code-only --raw-data <stub_to inject>: *\n", argv[0]);
    printf("\n");
    printf("* The stub is automatically an elf but you can indicate the --raw-data options if you want to inject directly assembly instructions from your stub\n");
}

int exit_clean(unsigned char *text_stub){

    free(text_stub);

    return 0;
}