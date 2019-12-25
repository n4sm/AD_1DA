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

void show_help(char **argv){
    printf("Usage : %s <target_file> <option> <stub_to_inject>\n", argv[0]);
    printf("Help : %s -h\n", argv[0]);
}

void help(char **argv){
    printf("AD_1DA is a modern tool made in order to obfuscate your elf binaries\n");
    printf("Help : \n");
    printf("\t\t%s <target_binary> [OPTIONS] <stub_to_inject> -v: Inject stub_to_inject and patching it as a stub injected in an elf with OPTIONS without the disassembly\n", argv[0]);
    printf("\t\t%s -h : Show this help\n", argv[0]);
    printf("\t\t%s <target_binary> -o <stub to inject>: Basic obfuscation (in work)\n", argv[0]);
    printf("\t\t%s <target_binary> -m <stub_to inject>: Create a new binary (<target_binary>.p4cked), which will be metamorphic and polymorphic\n", argv[0]);
    printf("\t\t%s <target_binary> -o <stub_to_inject> -pie: Inject stub_to_inject and patching it as a stub injected in a position independant executable binary\n", argv[0]);
    printf("\t\t%s <target_binary> -o <stub_to_inject>: Inject stub_to_inject and patching it as a stub injected in an elf\n", argv[0]);
    printf("\n");
}

int exit_clean(unsigned char *text_stub){

    free(text_stub);

    return 0;
}

void greetz(){
    printf(
    "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=- Developped by nasm - RE =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n"
    "Warning : This tool is made for educationals purposes only !\n"
    "\n"
    );
}