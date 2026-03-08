#ifndef HOOKEYE_H
#define HOOKEYE_H

#include <elf.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

enum hookeye_status {
    HOOKEYE_OK = 0,
    HOOKEYE_ERR_ARGUMENT,
    HOOKEYE_ERR_IO,
    HOOKEYE_ERR_NOMEM,
    HOOKEYE_ERR_PTRACE,
    HOOKEYE_ERR_ELF,
    HOOKEYE_ERR_UNSUPPORTED,
};

struct hookeye_memory_region {
    uintptr_t start;
    uintptr_t end;
    uint64_t offset;
    unsigned long inode;
    char perms[5];
    char dev[16];
    char *path;
    char *module;
};

struct hookeye_memory_map {
    size_t count;
    struct hookeye_memory_region *regions;
};

struct hookeye_plt_entry {
    uintptr_t slot_address;
    uintptr_t jump_address;
    uintptr_t module_base;
    uint32_t relocation_type;
    size_t symbol_index;
    const char *symbol_name;
    const char *module_name;
    bool resolved;
};

struct hookeye_target {
    pid_t pid;
    char exe_path[PATH_MAX];
    struct hookeye_memory_map maps;

    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdrs;
    size_t phdr_count;

    uintptr_t load_bias;
    uintptr_t image_start;
    uintptr_t image_end;

    Elf64_Dyn *dynamic_entries;
    size_t dynamic_count;

    Elf64_Sym *symtab;
    size_t symtab_size;
    size_t symtab_count;
    char *strtab;
    size_t strtab_size;

    void *jmprel;
    size_t jmprel_size;
    size_t jmprel_count;
    Elf64_Sxword jmprel_tag;

    uintptr_t pltgot_address;

    struct hookeye_plt_entry *entries;
    size_t entry_count;

    bool attached;
};

const char *hookeye_status_string(enum hookeye_status status);
enum hookeye_status hookeye_target_open(struct hookeye_target *target, pid_t pid);
void hookeye_target_close(struct hookeye_target *target);
void hookeye_target_dump(FILE *stream, const struct hookeye_target *target);

#endif
