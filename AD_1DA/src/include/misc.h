#ifndef AD_1DA_MISC_H
#define AD_1DA_MISC_H

// define

#define Elf64_EHDR 0x1111
#define Elf64_SHDR 0x2222
#define Elf64_PHDR 0x3333

#define FAILURE 0x1
#define SUCCESS 0x0

// misc prototype

int exit_clean(unsigned char *text_stub);

void log_ad(const char *s, int code);

int dump_struct(void *s, short type);

int dump_file(const char *name, unsigned char *to_dump, ssize_t len_dump);

#endif //AD_1DA_MISC_H