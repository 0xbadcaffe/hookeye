#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <dirent.h>

// Helper function to check if a struct dirent from /proc is a PID directory.
int is_pid_dir(const struct dirent *entry) {
    const char *p;

    for (p = entry->d_name; *p; p++) {
        if (!isdigit((unsigned char)*p))
            return 0;
    }

    return 1;
}

typedef struct _memory_region {
    void *start_address;
    void *end_address;
    char perms[5]; // ex. "r-xp", null-terminated
    off_t offset;
    char dev[12]; // major:minor ex: "08:02", null terminated.
    int inode;
    char *path;   /* Will be NULL if not present */
    char *module; /* Will be NULL if not present */
    Elf64_Ehdr *elfheader; // ELF and program header copied from target.
    Elf64_Phdr *pheader;   // only valid if this region the first region of an object/executable.
                           // They are lazy loaded by inject_shellcode in infect.c
} memory_region_t;

typedef struct _memory_map {
    uint32_t num_regions;
    memory_region_t *regions;
} memory_map_t;

/* Structure that holds all the necessary information about a pltgot entry
 * in order to infect it. An array of this is filled when parsing a target
 * in parse_remote_elf().
 */
typedef struct _pltgot_entry {
    void *slot_address;
    void *jump_address;
    void *module_base; // can be NULL if it cannot be retrieved.
    ssize_t symindex;  // can be -1 if not found
    // relindex???
    const char *symname; // can be NULL if cannot be retrieved.
    const char *module;  // can be NULL if module_base is NULL or lookup failed.
    int is_resolved;
    int is_infected; // so that it doesn't get infected twice.
} pltgot_entry_t;

typedef struct _TARGET {
    pid_t pid;
    void *base_address;
    memory_map_t maps;

    size_t sizeofimage;
    Elf64_Ehdr header;  // elf header copied from target.
    Elf64_Phdr *pheader; // program header copied from target.
    Elf64_Dyn *dyntable; // the DYNAMIC segment copied from target.

    void *plt_got_address;  // address of plt got in target VA space.
    Elf64_Addr *plt_got;    // the plt got copied from target.
    size_t plt_gotsz;       // size in bytes of the plt got.

    // Dynamic relocation information
    size_t pltrelsz;  // size in bytes of plt got relocation table used by dynamic linker.
    size_t numrelocs; // number of entries in the aforementioned reloc table. Redundant.
    union {           // table of relocation entries for plt got, copied from target.
        Elf64_Rel *pltreltable;
        Elf64_Rela *pltrelatable;
    } u1;
    // whether plt got relocations are of type Elf64_Rel or Elf64_Rela.
    // this determines how to interpret u1
    Elf64_Xword pltreltype; // can be either DT_REL or DT_RELA

    // Dynamic symbols table and string table
    size_t symtabsz; // size in bytes
    Elf64_Sym *symtab;
    size_t strtabsz; // size in bytes
    char *strtab;

    /* This array is filled with info about each pltgot entry.
     * It is used for infecting them. It is filled when parsing.
     */
    pltgot_entry_t *pltgot_entries;
} TARGET;

static int _parse_line(char *line, memory_region_t *region)
{
    int res, n = 0;
    unsigned long start_address, end_address;
    unsigned int off;

    region->module = NULL;
    region->path = NULL;

    res = sscanf(line, "%lx-%lx %4c %x %11s %d %n",
                 &start_address,
                 &end_address,
                 region->perms,
                 &off,
                 region->dev,
                 &region->inode,
                 &n);
    if (res < 4) {
        region->path = NULL;
        return 0;
    }

    char *path = line + n;
    size_t path_len = strlen(path);
    region->path = malloc(path_len + 1);
    if (!region->path)
        return 0;
    strcpy(region->path, path);
    region->perms[4] = '\0';

    region->start_address = (void *)start_address;
    region->end_address = (void *)end_address;
    region->offset = (off_t)off;
    region->elfheader = NULL;
    region->pheader = NULL;

    // fill region->module.
    if (*path != '[') {
        char *p = path + path_len - 1;
        while (*p != '/' && p >= path)
            p--;
        char *module = p;
        module++;
        size_t module_len = strlen(module);

        p = module + module_len;
        p--;
        if (*p == '\n')
            *p = '\0';
        while (*p != '.' && p > module)
            p--;
        if (*p == '.' && p > module)
            *p = '\0';
        module_len = strlen(module);

        region->module = malloc(module_len + 1);
        if (region->module == NULL)
            return 0;
        strcpy(region->module, module);
    }

    return 1;
}

void memory_map_free(memory_map_t *map)
{
    for (size_t i = 0; i < map->num_regions; i++) {
        free(map->regions[i].path);
        free(map->regions[i].module);
        free(map->regions[i].elfheader);
        free(map->regions[i].pheader);
    }
    free(map->regions);
    map->regions = NULL;
    map->num_regions = 0;
}

int memory_map_parse(memory_map_t *map, pid_t pid, uint32_t call_num)
{
    fprintf(stderr, "memory_map_parse call num %u\n", call_num);

#define NSLOTS 23
    uint32_t num_regions = 0;
    uint32_t remaining_slots = 0;
    FILE *f = NULL;
    char *path = NULL, *line = NULL;
    size_t n = 0;
    ssize_t nread = 0;
    memory_region_t *regions = NULL;

    memset((void *)map, 0x00, sizeof(memory_map_t));

    if (pid < 0) {
        if (!(f = fopen("/proc/self/maps", "r")))
            goto _error;
    } else {
        if (asprintf(&path, "/proc/%lu/maps", (unsigned long)pid) == -1)
            goto _error;

        if (!(f = fopen(path, "r")))
            goto _error;
        free(path);
        path = NULL;
    }

    size_t size = NSLOTS * sizeof(memory_region_t);
    regions = (memory_region_t *)malloc(size);
    if (!regions)
        goto _error;
    remaining_slots = NSLOTS;
    num_regions = 0;

    n = 128;
    line = malloc(n);
    if (!line)
        goto _error;

    errno = 0;
    while ((nread = getline(&line, &n, f)) != -1) {
        (void)nread;
        if (!_parse_line(line, &regions[num_regions]))
            goto _error;

        num_regions++;
        remaining_slots--;
        if (remaining_slots == 0) { // dynamically grow the array...
            size += NSLOTS * sizeof(memory_region_t);
            void *p = realloc(regions, size);
            if (!p)
                goto _error;
            regions = (memory_region_t *)p;
            remaining_slots = NSLOTS;
        }
    }
    if (ferror(f) || num_regions == 0)
        goto _error;

    free(line);
    line = NULL;
    map->regions = regions;
    map->num_regions = num_regions;

    fclose(f);
    return 1;
_error:
    if (f)
        fclose(f);
    free(path);
    free(line);
    if (regions) {
        for (uint32_t i = 0; i < num_regions; ++i) {
            free(regions[i].path);
            free(regions[i].module);
            free(regions[i].elfheader);
            free(regions[i].pheader);
        }
        free(regions);
    }
    map->regions = NULL;
    map->num_regions = 0;
    return 0;
#undef NSLOTS
}

/* Given the base address of a module in target va space,
 * it returns a string with the name of said module.
 * returns NULL when the module is a special region in the memory map:
 * [heap], [stack]... instead of being mapped from a file.
 */
static const char *_get_module_name_from_base(TARGET *target, void *baseaddr)
{
    memory_map_t *maps = &target->maps;
    for (uint32_t i = 0; i < maps->num_regions; i++) {
        if (maps->regions[i].start_address == baseaddr)
            return maps->regions[i].module; // will be null if special region.
    }
    return NULL;
}

/* Given a pointer addr somewhere within target va space,
 * return the base address of the module where that pointer
 * lies.
 * For instance, if addr is the address of a libc function,
 * it returns the base address of libc.
 * Returns NULL on failure.
 */
void *target_find_base(TARGET *target, void *addr)
{
    size_t val = (size_t)addr;
    memory_region_t *belong_region = NULL;
    for (uint32_t i = 0; i < target->maps.num_regions; i++) {
        memory_region_t *r = &target->maps.regions[i];
        if (val < (size_t)r->end_address && val >= (size_t)r->start_address)
            belong_region = r;
    }
    if (!belong_region)
        return NULL;

    for (uint32_t i = 0; i < target->maps.num_regions; i++) {
        memory_region_t *r = &target->maps.regions[i];
        if (strcmp(r->dev, belong_region->dev) == 0 && r->inode == belong_region->inode)
            return r->start_address;
    }
    return NULL;
}

const char *target_get_symbol_name(TARGET *target, ssize_t symindex)
{
    if (symindex < 0)
        return NULL;
    Elf64_Sym *sym = &target->symtab[symindex];
    uint32_t nameoffset = sym->st_name;
    return &target->strtab[nameoffset];
}

/* Given a pointer within the address space of target,
 * returns a boolean telling whether the pointer falls within
 * the image of the main executable or not.
 */
int is_address_in_target(TARGET *target, void *addr)
{
    return (((size_t)addr) < ((size_t)target->base_address + target->sizeofimage)) &&
           (((size_t)addr) >= ((size_t)target->base_address));
}

static int _target_parse_pltgot(TARGET *target)
{
    fprintf(stderr, "_target_parse_pltgot\n");

    if (target->pltgot_entries)
        free(target->pltgot_entries);

    // First 3 entries are reserved. See SysV amd64 ABI supplement.
    size_t numentries = (target->plt_gotsz / sizeof(Elf64_Addr)) - 3;
    pltgot_entry_t *entries = malloc(numentries * sizeof(pltgot_entry_t));
    if (!entries)
        return 0;

    target->pltgot_entries = entries;

    Elf64_Addr *p = target->plt_got + 3;
    for (size_t i = 0; i < numentries; i++) {
        pltgot_entry_t *entry = &entries[i];
        Elf64_Addr jmpaddr = *p;
        void *slot_address =
            (void *)(((size_t)target->plt_got_address) + ((size_t)p - (size_t)target->plt_got));
        entry->slot_address = slot_address;
        entry->jump_address = (void *)jmpaddr;

        ssize_t symindex = -1; // invalid index

        // Find the symbol table index for the current pltgot entry.
        for (size_t ri = 0; ri < target->numrelocs; ri++) {
            Elf64_Addr r_offset;
            uint64_t r_info;
            void *fixaddr;

            if (target->pltreltype == DT_REL) {
                r_offset = target->u1.pltreltable[ri].r_offset;
                r_info = target->u1.pltreltable[ri].r_info;
            } else if (target->pltreltype == DT_RELA) {
                r_offset = target->u1.pltrelatable[ri].r_offset;
                r_info = target->u1.pltrelatable[ri].r_info;
            } else {
                continue;
            }

            fixaddr = (void *)r_offset;
            if (target->header.e_type == ET_DYN) // the binary is pie so va is relative.
                fixaddr = (void *)((size_t)fixaddr + (size_t)target->base_address);

            if (fixaddr == slot_address) {
                symindex = (ssize_t)ELF64_R_SYM(r_info);
                break;
            }
        }

        entry->symindex = symindex;
        entry->symname = target_get_symbol_name(target, symindex);
        entry->module_base = target_find_base(target, (void *)jmpaddr);
        entry->module = _get_module_name_from_base(target, entry->module_base);
        entry->is_resolved = !is_address_in_target(target, entry->jump_address);
        entry->is_infected = 0;

        p++;
    }

    return 1;
}

int ReadProcessMemory(pid_t pid, const void *base_address,
                      void *buffer, size_t size)
{
#define _WORD_SIZE (sizeof(long)) // ptrace() returns a word in a long.
    size_t sb, remaining;
    long *raddr, *laddr;

    raddr = (long *)base_address;
    laddr = (long *)buffer;

    sb = size / _WORD_SIZE;
    remaining = size % _WORD_SIZE;

    for (size_t i = 0; i < sb; i++) {
        errno = 0;
        long res = ptrace(PTRACE_PEEKTEXT, pid, (void *)raddr, 0);
        if (errno)
            return 0;

        *laddr = res;
        raddr += 1;
        laddr += 1;
    }

    if (remaining) {
        errno = 0;
        long res = ptrace(PTRACE_PEEKTEXT, pid, (void *)raddr, 0);
        if (errno)
            return 0;

        char *p = (char *)laddr;
        for (size_t i = 0; i < remaining; i++) {
            *p = (char)((res >> (i * 8)) & 0xFF);
            p++;
        }
    }

    return 1;
#undef _WORD_SIZE
}

int target_init(TARGET *target, pid_t pid)
{
    // so that we can call free() after an error.
    // Unallocated buffers will be NULL so free is no-op.
    memset((void *)target, 0x00, sizeof(TARGET));

    target->pid = pid;
    if (!memory_map_parse(&target->maps, target->pid, 1)) {
        fprintf(stderr, "[-] Cannot parse memory map of target %d.\n", pid);
        return 0;
    }
    if (target->maps.num_regions == 0) {
        fprintf(stderr, "[-] Empty memory map for target %d.\n", pid);
        memory_map_free(&target->maps);
        return 0;
    }

    target->base_address = target->maps.regions[0].start_address;

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        perror("ptrace(PTRACE_ATTACH)");
        memory_map_free(&target->maps);
        return 0;
    }
    waitpid(pid, NULL, 0);

    return 1;
}

void target_free(TARGET *target)
{
    free(target->pheader);
    target->pheader = NULL;
    free(target->dyntable);
    target->dyntable = NULL;
    free(target->plt_got);
    target->plt_got = NULL;
    free(target->u1.pltrelatable);
    target->u1.pltrelatable = NULL;
    free(target->symtab);
    target->symtab = NULL;
    free(target->strtab);
    target->strtab = NULL;
    free(target->pltgot_entries);
    target->pltgot_entries = NULL;

    memory_map_free(&target->maps);

    if (target->pid > 0) {
        ptrace(PTRACE_DETACH, target->pid, 0, 0);
    }
}

int target_parse_remote_elf(TARGET *target)
{
    void *base_address = target->base_address;
    pid_t pid = target->pid;

    fprintf(stderr, "[+] Base address of pid %lu is %p\n",
            (unsigned long)pid, base_address);
    /* Copy the ELF header from the remote process */
    Elf64_Ehdr *header = &target->header;
    if (!ReadProcessMemory(pid, base_address, (void *)header,
                           sizeof(Elf64_Ehdr)))
        goto _error;

    if (((char *)header)[4] != 0x02) {
        fprintf(stderr, "[-] This program only works on 64bit processes!\n");
        goto _error;
    }

    /* Copy program header from remote process */
    void *pheader_address = (void *)(((char *)base_address) + header->e_phoff);
    Elf64_Phdr *pheader;
    pheader = (Elf64_Phdr *)malloc(header->e_phnum * sizeof(Elf64_Phdr));
    if (!pheader)
        goto _error;

    target->pheader = pheader;
    if (!ReadProcessMemory(pid, pheader_address, (void *)pheader,
                           sizeof(Elf64_Phdr) * header->e_phnum))
        goto _error;

    /* Traverse program header to look for dynamic segment and to calculate
     * size of image
     */
    Elf64_Phdr *ph_dynamic = NULL;
    Elf64_Phdr *firstload, *lastload;
    firstload = lastload = NULL;
    for (int i = 0; i < header->e_phnum; i++) {
        Elf64_Phdr *ph = &pheader[i];
        if (ph->p_type == PT_LOAD || ph->p_type == PT_DYNAMIC) {
            if (firstload == NULL)
                firstload = ph;
            lastload = ph;
            if (ph->p_type == PT_DYNAMIC)
                ph_dynamic = ph;
        }
    }
    if (!firstload || !lastload)
        goto _error;
    if (!ph_dynamic) {
        fprintf(stderr, "[-] Could not find DYNAMIC information.\n");
        goto _error;
    }

    target->sizeofimage = (size_t)(((size_t)lastload->p_vaddr + lastload->p_memsz) -
                                   (size_t)firstload->p_vaddr);

    void *dynamic_address; // Address of DYNAMIC Section in target va.
    dynamic_address = (void *)ph_dynamic->p_vaddr;
    uint64_t dynamic_size = ph_dynamic->p_memsz;
    if (header->e_type == ET_DYN) {
        // target is PIE so segment addresses are base-relative.
        dynamic_address = (void *)(((char *)dynamic_address) + ((size_t)base_address));
        fprintf(stderr, "[+] Target process is PIE\n");
    }

    fprintf(stderr, "[+] DYNAMIC section at %p (size %llu bytes)\n",
            dynamic_address, (unsigned long long)dynamic_size);

    /* Copy dynamic section from target */
    Elf64_Dyn *dyntable = malloc(dynamic_size);
    if (!dyntable)
        goto _error;

    target->dyntable = dyntable;
    if (!ReadProcessMemory(pid, dynamic_address, dyntable, dynamic_size))
        goto _error;

    /* Find dynamic information from DYNAMIC section and copy it.
     *  ex. pointers to dynamic symbol table, dynamic relocations for pltgot...
     */
    size_t pltrelsz = 0;
    void *pltreltable_address = NULL;
    void *plt_got_address = NULL;
    Elf64_Xword pltreltype = 0;
    int foundRelTable = 0, foundRelSize = 0, foundRelType = 0;

    void *symtab_address = NULL;
    void *symhash_address = NULL;
    void *strtab_address = NULL;
    size_t strtabsz = 0;
    int foundStrtabsz = 0;

    // Note: Even if target is PIE, VAs in DYNAMIC segment are already absolute.
    for (Elf64_Dyn *dentry = dyntable; dentry->d_tag != DT_NULL; dentry++) {
        switch (dentry->d_tag) {
        case DT_PLTGOT: // address of the PLT GOT
            plt_got_address = (void *)dentry->d_un.d_ptr;
            break;
        case DT_JMPREL: // address of relocation table
            foundRelTable = 1;
            pltreltable_address = (void *)dentry->d_un.d_ptr;
            fprintf(stderr, "found plt rel table %p\n", pltreltable_address);
            break;
        case DT_PLTREL: // type of relocation
            foundRelType = 1;
            pltreltype = dentry->d_un.d_val;
            break;
        case DT_PLTRELSZ: // size in bytes of relocation table for plt got
            foundRelSize = 1;
            pltrelsz = dentry->d_un.d_val;
            break;
        case DT_SYMTAB: // address of dynamic symbol table
            symtab_address = (void *)dentry->d_un.d_ptr;
            break;
        case DT_HASH: // address of symbol hash table
            symhash_address = (void *)dentry->d_un.d_ptr;
            break;
        case DT_STRTAB: // address of string table
            strtab_address = (void *)dentry->d_un.d_ptr;
            break;
        case DT_STRSZ: // size in bytes of string table
            foundStrtabsz = 1;
            strtabsz = (size_t)dentry->d_un.d_val;
            break;
        default:
            break;
        }
    }
    if (!plt_got_address) {
        fprintf(stderr, "[-] Could not find PLT GOT of target.\n");
        goto _error;
    }
    target->plt_got_address = plt_got_address;

    if (!foundRelTable || !foundRelType || !foundRelSize) {
        fprintf(stderr, "[-] Could not find dynamic relocation information of target.\n");
        goto _error;
    }

    if (!symtab_address || !strtab_address || !foundStrtabsz) {
        fprintf(stderr, "[-] Could not find dynamic symbol table or string table\n");
        goto _error;
    }

    // Copy plt got relocation table from target.
    char *pltreltable = (char *)malloc(pltrelsz);
    if (!pltreltable)
        goto _error;

    if (!ReadProcessMemory(pid, pltreltable_address, pltreltable, pltrelsz))
        goto _error;

    // Copy string table from target
    target->strtab = malloc(strtabsz);
    if (!target->strtab)
        goto _error;

    if (!ReadProcessMemory(pid, strtab_address, target->strtab, strtabsz))
        goto _error;

    target->pltreltype = pltreltype;
    target->pltrelsz = pltrelsz;
    if (pltreltype == DT_REL)
        target->u1.pltreltable = (Elf64_Rel *)pltreltable;
    else if (pltreltype == DT_RELA)
        target->u1.pltrelatable = (Elf64_Rela *)pltreltable;
    else
        fprintf(stderr, "[-] PLT relocation type corruption detected!\n");

    fprintf(stderr, "[+] Dynamic relocation table for PLT GOT at %p (%llu bytes) ",
            pltreltable_address, (unsigned long long)pltrelsz);
    fprintf(stderr, pltreltype == DT_REL ? "DT_REL\n" : "DT_RELA\n");

    fprintf(stderr, "[+] Dynamic symbol table at %p\n", symtab_address);
    fprintf(stderr, "[+] Dynamic string table at %p (size %llu bytes)\n",
            strtab_address, (unsigned long long)strtabsz);

    // Calculate numrelocs
    size_t numrelocs = target->pltrelsz;
    if (target->pltreltype == DT_REL)
        numrelocs /= sizeof(Elf64_Rel);
    else if (target->pltreltype == DT_RELA)
        numrelocs /= sizeof(Elf64_Rela);
    else
        goto _error;
    target->numrelocs = numrelocs;

    /* There are 3 reserved entries at the beginning according to amd64 ABI supplement. */
    target->plt_gotsz = (numrelocs + 3) * sizeof(Elf64_Addr);

    /*
     * Calculate the size of the dynamic symbol table.
     * -------------------------------------------------
     * To do so we use the symbol hash table. ELF specs say:
     * "The number of symbol table entries should equal nchain (in hash table)"
     */
    if (symhash_address) {
        Elf64_Word data[2];
        if (!ReadProcessMemory(pid, symhash_address, data, sizeof(data)))
            goto _error;
        Elf64_Word nchain = data[1]; // number of symbols
        target->symtabsz = (size_t)nchain * sizeof(Elf64_Sym);
        fprintf(stderr,
                "[DEBUG] Found hash table, nchain=nsyms=%u, symtabsz(bytes)=%zu\n",
                nchain, target->symtabsz);
    } else {
        if ((size_t)strtab_address <= (size_t)symtab_address) {
            fprintf(stderr, "[-] Cannot calculate size of dynamic symbol table.\n");
            goto _error;
        }
        target->symtabsz = (size_t)strtab_address - (size_t)symtab_address;
    }

    fprintf(stderr, "[+] Estimated size of the PLT GOT: %llu bytes (%lu entries)\n",
            (unsigned long long)target->plt_gotsz, (unsigned long)(numrelocs + 3));
    fprintf(stderr, "[+] Estimated size of dynamic symbol table: %llu bytes (%lu entries)\n",
            (unsigned long long)target->symtabsz,
            (unsigned long)(target->symtabsz / sizeof(Elf64_Sym)));

    // Perform the memory transfers.
    target->plt_got = malloc(target->plt_gotsz);
    if (!target->plt_got)
        goto _error;

    target->symtab = malloc(target->symtabsz);
    if (!target->symtab)
        goto _error;

    if (!ReadProcessMemory(pid, plt_got_address, target->plt_got, target->plt_gotsz))
        goto _error;
    if (!ReadProcessMemory(pid, symtab_address, target->symtab, target->symtabsz))
        goto _error;

    /* Fill the array target.pltgot_entries with the necessary info about
     * each pltgot entry needed to infect it.
     */
    if (!_target_parse_pltgot(target))
        goto _error;

    // THE END
    return 1;
_error:
    target_free(target);
    return 0;
}

void dump_pltgot(pid_t pid)
{
    TARGET target;

    if (!target_init(&target, pid)) {
        fprintf(stderr, "[-] target_init failed for pid %d\n", pid);
        return;
    }

    if (!target_parse_remote_elf(&target)) {
        fprintf(stderr, "[-] target_parse_remote_elf failed for pid %d\n", pid);
        // target_parse_remote_elf() already called target_free()
        return;
    }

    pltgot_entry_t *entries = target.pltgot_entries;
    size_t numentries = (target.plt_gotsz / sizeof(Elf64_Addr)) - 3;

    for (size_t i = 0; i < numentries; i++) {
        pltgot_entry_t *entry = &entries[i];

        if (entry->symindex < 0) {
            fprintf(stderr,
                    "[%lu] %p:\t%p\t(sym. #?)\tCANNOT FIND SYMBOL\n",
                    i, entry->slot_address, entry->jump_address);
        } else {
            const char *module = entry->is_resolved ? entry->module : "(unresolved)";
            fprintf(stderr,
                    "[%lu] %p:\t%p\t(sym. #%ld)\t%s@%s\n",
                    i,
                    entry->slot_address,
                    entry->jump_address,
                    (long)entry->symindex,
                    entry->symname ? entry->symname : "(null)",
                    module ? module : "(null)");
        }
    }

    target_free(&target);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    char *endptr = NULL;
    errno = 0;
    long val = strtol(argv[1], &endptr, 10);
    if (errno != 0 || *endptr != '\0' || val <= 0) {
        fprintf(stderr, "Invalid pid: %s\n", argv[1]);
        return 1;
    }

    pid_t pid = (pid_t)val;
    dump_pltgot(pid);
    return 0;
}
