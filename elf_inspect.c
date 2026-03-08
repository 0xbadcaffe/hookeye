#include "hookeye_internal.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static_assert(sizeof(Elf64_Addr) == sizeof(uint64_t), "unexpected Elf64_Addr size");

static void hookeye_debugf(const char *format, ...) {
    const char *enabled = getenv("HOOKEYE_DEBUG");
    if (enabled == NULL || strcmp(enabled, "0") == 0) {
        return;
    }

    va_list args;
    va_start(args, format);
    fputs("[hookeye] ", stderr);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
}

struct hookeye_dynamic_info {
    uintptr_t symtab;
    uintptr_t strtab;
    uintptr_t hash;
    uintptr_t gnu_hash;
    uintptr_t jmprel;
    uintptr_t pltgot;
    size_t strsz;
    size_t syment;
    size_t symsz;
    size_t pltrelsz;
    size_t relent;
    size_t relaent;
    Elf64_Sxword pltrel;
    bool have_symtab;
    bool have_strtab;
    bool have_strsz;
    bool have_syment;
    bool have_pltrel;
    bool have_pltrelsz;
    bool have_jmprel;
};

static uintptr_t hookeye_page_floor(uintptr_t value, size_t page_size) {
    return value & ~((uintptr_t)page_size - 1U);
}

static bool hookeye_address_in_main_image(const struct hookeye_target *target, uintptr_t address) {
    return target->image_start <= address && address < target->image_end;
}

static uintptr_t hookeye_adjust_vaddr(const struct hookeye_target *target, uintptr_t value) {
    if (value == 0U) {
        return 0U;
    }

    if (hookeye_memory_map_find_region(&target->maps, value) != NULL) {
        return value;
    }

    return value + target->load_bias;
}

static enum hookeye_status hookeye_read_exact(
    const struct hookeye_target *target,
    uintptr_t remote_address,
    void *buffer,
    size_t size) {
    enum hookeye_status status = hookeye_remote_read(target, remote_address, buffer, size);
    if (status != HOOKEYE_OK) {
        memset(buffer, 0, size);
    }
    return status;
}

static const struct hookeye_memory_region *hookeye_find_main_base_region(
    const struct hookeye_target *target) {
    const struct hookeye_memory_region *best = hookeye_memory_map_find_file_region(
        &target->maps,
        target->exe_path,
        0U);
    if (best != NULL) {
        return best;
    }

    for (size_t index = 0; index < target->maps.count; ++index) {
        const struct hookeye_memory_region *region = &target->maps.regions[index];
        if (region->path != NULL && strcmp(region->path, target->exe_path) == 0) {
            return region;
        }
    }

    return NULL;
}

static enum hookeye_status hookeye_read_program_headers(struct hookeye_target *target, uintptr_t image_base) {
    if (hookeye_read_exact(target, image_base, &target->ehdr, sizeof(target->ehdr)) != HOOKEYE_OK) {
        return HOOKEYE_ERR_IO;
    }

    if (memcmp(target->ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        hookeye_debugf("invalid ELF magic");
        return HOOKEYE_ERR_ELF;
    }
    if (target->ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        hookeye_debugf("unsupported ELF class %u", target->ehdr.e_ident[EI_CLASS]);
        return HOOKEYE_ERR_UNSUPPORTED;
    }
    if (target->ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        hookeye_debugf("unsupported ELF data encoding %u", target->ehdr.e_ident[EI_DATA]);
        return HOOKEYE_ERR_UNSUPPORTED;
    }
    if (target->ehdr.e_phentsize != sizeof(Elf64_Phdr) || target->ehdr.e_phnum == 0U) {
        hookeye_debugf("bad program header table: entsize=%u phnum=%u",
                       target->ehdr.e_phentsize,
                       target->ehdr.e_phnum);
        return HOOKEYE_ERR_ELF;
    }

    size_t phdr_bytes = (size_t)target->ehdr.e_phnum * sizeof(Elf64_Phdr);
    target->phdrs = malloc(phdr_bytes);
    if (target->phdrs == NULL) {
        return HOOKEYE_ERR_NOMEM;
    }

    enum hookeye_status status = hookeye_read_exact(
        target,
        image_base + target->ehdr.e_phoff,
        target->phdrs,
        phdr_bytes);
    if (status != HOOKEYE_OK) {
        return status;
    }

    target->phdr_count = target->ehdr.e_phnum;
    return HOOKEYE_OK;
}

static enum hookeye_status hookeye_compute_load_bias(struct hookeye_target *target) {
    const Elf64_Phdr *lowest_load = NULL;
    const Elf64_Phdr *dynamic_phdr = NULL;
    uintptr_t image_start = UINTPTR_MAX;
    uintptr_t image_end = 0U;

    for (size_t index = 0; index < target->phdr_count; ++index) {
        const Elf64_Phdr *phdr = &target->phdrs[index];
        if (phdr->p_type == PT_LOAD) {
            if (lowest_load == NULL || phdr->p_vaddr < lowest_load->p_vaddr) {
                lowest_load = phdr;
            }
        } else if (phdr->p_type == PT_DYNAMIC) {
            dynamic_phdr = phdr;
        }
    }

    if (lowest_load == NULL || dynamic_phdr == NULL) {
        hookeye_debugf("missing PT_LOAD or PT_DYNAMIC");
        return HOOKEYE_ERR_ELF;
    }

    long page_size_raw = sysconf(_SC_PAGESIZE);
    size_t page_size = (page_size_raw > 0) ? (size_t)page_size_raw : 4096U;

    uint64_t segment_offset = hookeye_page_floor(lowest_load->p_offset, page_size);
    const struct hookeye_memory_region *segment_region = hookeye_memory_map_find_file_region(
        &target->maps,
        target->exe_path,
        segment_offset);
    if (segment_region == NULL) {
        const struct hookeye_memory_region *base_region = hookeye_find_main_base_region(target);
        if (base_region == NULL) {
            hookeye_debugf("failed to locate base mapping for %s", target->exe_path);
            return HOOKEYE_ERR_IO;
        }
        segment_region = base_region;
    }

    uintptr_t truncated_vaddr = hookeye_page_floor(lowest_load->p_vaddr, page_size);
    target->load_bias = segment_region->start - truncated_vaddr;

    for (size_t index = 0; index < target->phdr_count; ++index) {
        const Elf64_Phdr *phdr = &target->phdrs[index];
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        uintptr_t start = target->load_bias + phdr->p_vaddr;
        uintptr_t end = start + phdr->p_memsz;
        if (start < image_start) {
            image_start = start;
        }
        if (end > image_end) {
            image_end = end;
        }
    }

    if (image_start == UINTPTR_MAX || image_end <= image_start) {
        hookeye_debugf("invalid image bounds start=%#" PRIxPTR " end=%#" PRIxPTR, image_start, image_end);
        return HOOKEYE_ERR_ELF;
    }

    target->image_start = image_start;
    target->image_end = image_end;

    uintptr_t dynamic_address = target->load_bias + dynamic_phdr->p_vaddr;
    size_t dynamic_size = (size_t)dynamic_phdr->p_memsz;
    if (dynamic_size == 0U || dynamic_size % sizeof(Elf64_Dyn) != 0U) {
        hookeye_debugf("invalid dynamic size=%zu", dynamic_size);
        return HOOKEYE_ERR_ELF;
    }

    target->dynamic_entries = malloc(dynamic_size);
    if (target->dynamic_entries == NULL) {
        return HOOKEYE_ERR_NOMEM;
    }
    enum hookeye_status status = hookeye_read_exact(
        target,
        dynamic_address,
        target->dynamic_entries,
        dynamic_size);
    if (status != HOOKEYE_OK) {
        return status;
    }

    target->dynamic_count = dynamic_size / sizeof(Elf64_Dyn);
    return HOOKEYE_OK;
}

static enum hookeye_status hookeye_parse_dynamic_info(
    struct hookeye_target *target,
    struct hookeye_dynamic_info *info) {
    memset(info, 0, sizeof(*info));

    for (size_t index = 0; index < target->dynamic_count; ++index) {
        const Elf64_Dyn *dyn = &target->dynamic_entries[index];
        if (dyn->d_tag == DT_NULL) {
            break;
        }

        switch (dyn->d_tag) {
            case DT_SYMTAB:
                info->symtab = hookeye_adjust_vaddr(target, dyn->d_un.d_ptr);
                info->have_symtab = true;
                break;
            case DT_STRTAB:
                info->strtab = hookeye_adjust_vaddr(target, dyn->d_un.d_ptr);
                info->have_strtab = true;
                break;
            case DT_STRSZ:
                info->strsz = (size_t)dyn->d_un.d_val;
                info->have_strsz = true;
                break;
            case DT_SYMENT:
                info->syment = (size_t)dyn->d_un.d_val;
                info->have_syment = true;
                break;
            case DT_SYMTABSZ:
                info->symsz = (size_t)dyn->d_un.d_val;
                break;
            case DT_HASH:
                info->hash = hookeye_adjust_vaddr(target, dyn->d_un.d_ptr);
                break;
            case DT_GNU_HASH:
                info->gnu_hash = hookeye_adjust_vaddr(target, dyn->d_un.d_ptr);
                break;
            case DT_JMPREL:
                info->jmprel = hookeye_adjust_vaddr(target, dyn->d_un.d_ptr);
                info->have_jmprel = true;
                break;
            case DT_PLTRELSZ:
                info->pltrelsz = (size_t)dyn->d_un.d_val;
                info->have_pltrelsz = true;
                break;
            case DT_PLTREL:
                info->pltrel = (Elf64_Sxword)dyn->d_un.d_val;
                info->have_pltrel = true;
                break;
            case DT_RELENT:
                info->relent = (size_t)dyn->d_un.d_val;
                break;
            case DT_RELAENT:
                info->relaent = (size_t)dyn->d_un.d_val;
                break;
            case DT_PLTGOT:
                info->pltgot = hookeye_adjust_vaddr(target, dyn->d_un.d_ptr);
                break;
            default:
                break;
        }
    }

    if (!info->have_symtab || !info->have_strtab || !info->have_strsz ||
        !info->have_syment || !info->have_jmprel || !info->have_pltrelsz ||
        !info->have_pltrel) {
        hookeye_debugf("dynamic tags missing symtab=%d strtab=%d strsz=%d syment=%d jmprel=%d pltrelsz=%d pltrel=%d",
                       info->have_symtab,
                       info->have_strtab,
                       info->have_strsz,
                       info->have_syment,
                       info->have_jmprel,
                       info->have_pltrelsz,
                       info->have_pltrel);
        return HOOKEYE_ERR_ELF;
    }
    if (info->syment != sizeof(Elf64_Sym)) {
        hookeye_debugf("unexpected DT_SYMENT=%zu", info->syment);
        return HOOKEYE_ERR_UNSUPPORTED;
    }
    if (info->pltrel != DT_REL && info->pltrel != DT_RELA) {
        hookeye_debugf("unexpected DT_PLTREL=%ld", (long)info->pltrel);
        return HOOKEYE_ERR_UNSUPPORTED;
    }
    if ((info->pltrel == DT_REL && info->relent != 0U && info->relent != sizeof(Elf64_Rel)) ||
        (info->pltrel == DT_RELA && info->relaent != 0U && info->relaent != sizeof(Elf64_Rela))) {
        hookeye_debugf("unexpected relocation entry size relent=%zu relaent=%zu",
                       info->relent,
                       info->relaent);
        return HOOKEYE_ERR_UNSUPPORTED;
    }

    target->pltgot_address = info->pltgot;
    return HOOKEYE_OK;
}

static enum hookeye_status hookeye_resolve_symtab_size(
    struct hookeye_target *target,
    const struct hookeye_dynamic_info *info,
    size_t *symtab_size) {
    if (info->symsz != 0U) {
        *symtab_size = info->symsz;
        return HOOKEYE_OK;
    }

    if (info->hash == 0U) {
        if (info->gnu_hash == 0U) {
            return HOOKEYE_ERR_ELF;
        }

        Elf64_Word header[4];
        enum hookeye_status status = hookeye_read_exact(target, info->gnu_hash, header, sizeof(header));
        if (status != HOOKEYE_OK) {
            return status;
        }

        Elf64_Word nbuckets = header[0];
        Elf64_Word symoffset = header[1];
        Elf64_Word bloom_size = header[2];

        size_t buckets_offset = sizeof(header) + (size_t)bloom_size * sizeof(Elf64_Xword);
        size_t buckets_size = (size_t)nbuckets * sizeof(Elf64_Word);
        Elf64_Word *buckets = malloc(buckets_size);
        if (buckets == NULL) {
            return HOOKEYE_ERR_NOMEM;
        }

        status = hookeye_read_exact(target, info->gnu_hash + buckets_offset, buckets, buckets_size);
        if (status != HOOKEYE_OK) {
            free(buckets);
            return status;
        }

        uintptr_t chain_base = info->gnu_hash + buckets_offset + buckets_size;
        size_t max_symbol_index = symoffset;

        for (Elf64_Word bucket_index = 0; bucket_index < nbuckets; ++bucket_index) {
            Elf64_Word symbol_index = buckets[bucket_index];
            if (symbol_index < symoffset) {
                continue;
            }

            for (;;) {
                Elf64_Word chain = 0;
                status = hookeye_read_exact(
                    target,
                    chain_base + ((size_t)(symbol_index - symoffset) * sizeof(chain)),
                    &chain,
                    sizeof(chain));
                if (status != HOOKEYE_OK) {
                    free(buckets);
                    return status;
                }

                if ((size_t)symbol_index > max_symbol_index) {
                    max_symbol_index = symbol_index;
                }
                if ((chain & 1U) != 0U) {
                    break;
                }
                ++symbol_index;
            }
        }

        free(buckets);
        *symtab_size = (max_symbol_index + 1U) * sizeof(Elf64_Sym);
        return HOOKEYE_OK;
    }

    Elf64_Word hash_header[2];
    enum hookeye_status status = hookeye_read_exact(target, info->hash, hash_header, sizeof(hash_header));
    if (status != HOOKEYE_OK) {
        return status;
    }

    *symtab_size = (size_t)hash_header[1] * sizeof(Elf64_Sym);
    return HOOKEYE_OK;
}

static enum hookeye_status hookeye_read_symbols_and_strings(
    struct hookeye_target *target,
    const struct hookeye_dynamic_info *info) {
    size_t symtab_size = 0U;
    enum hookeye_status status = hookeye_resolve_symtab_size(target, info, &symtab_size);
    if (status != HOOKEYE_OK) {
        return status;
    }
    if (symtab_size == 0U || symtab_size % sizeof(Elf64_Sym) != 0U) {
        hookeye_debugf("bad dynsym size=%zu", symtab_size);
        return HOOKEYE_ERR_ELF;
    }

    target->symtab = malloc(symtab_size);
    target->strtab = malloc(info->strsz);
    if (target->symtab == NULL || target->strtab == NULL) {
        return HOOKEYE_ERR_NOMEM;
    }

    status = hookeye_read_exact(target, info->symtab, target->symtab, symtab_size);
    if (status != HOOKEYE_OK) {
        return status;
    }
    status = hookeye_read_exact(target, info->strtab, target->strtab, info->strsz);
    if (status != HOOKEYE_OK) {
        return status;
    }

    target->symtab_size = symtab_size;
    target->symtab_count = symtab_size / sizeof(Elf64_Sym);
    target->strtab_size = info->strsz;
    return HOOKEYE_OK;
}

static const char *hookeye_symbol_name(const struct hookeye_target *target, size_t symbol_index) {
    if (symbol_index >= target->symtab_count) {
        return NULL;
    }

    uint32_t name_offset = target->symtab[symbol_index].st_name;
    if (name_offset >= target->strtab_size) {
        return NULL;
    }
    return target->strtab + name_offset;
}

static enum hookeye_status hookeye_read_jmprel(struct hookeye_target *target, const struct hookeye_dynamic_info *info) {
    size_t entry_size = (info->pltrel == DT_REL) ? sizeof(Elf64_Rel) : sizeof(Elf64_Rela);
    if (info->pltrelsz == 0U || info->pltrelsz % entry_size != 0U) {
        hookeye_debugf("bad jmprel size=%zu entry_size=%zu", info->pltrelsz, entry_size);
        return HOOKEYE_ERR_ELF;
    }

    target->jmprel = malloc(info->pltrelsz);
    if (target->jmprel == NULL) {
        return HOOKEYE_ERR_NOMEM;
    }

    enum hookeye_status status = hookeye_read_exact(target, info->jmprel, target->jmprel, info->pltrelsz);
    if (status != HOOKEYE_OK) {
        return status;
    }

    target->jmprel_size = info->pltrelsz;
    target->jmprel_count = info->pltrelsz / entry_size;
    target->jmprel_tag = info->pltrel;
    return HOOKEYE_OK;
}

static enum hookeye_status hookeye_build_plt_entries(struct hookeye_target *target) {
    target->entries = calloc(target->jmprel_count, sizeof(*target->entries));
    if (target->entries == NULL) {
        return HOOKEYE_ERR_NOMEM;
    }

    target->entry_count = target->jmprel_count;

    for (size_t index = 0; index < target->jmprel_count; ++index) {
        Elf64_Addr r_offset = 0;
        Elf64_Xword r_info = 0;
        if (target->jmprel_tag == DT_REL) {
            const Elf64_Rel *rel = &((const Elf64_Rel *)target->jmprel)[index];
            r_offset = rel->r_offset;
            r_info = rel->r_info;
        } else {
            const Elf64_Rela *rela = &((const Elf64_Rela *)target->jmprel)[index];
            r_offset = rela->r_offset;
            r_info = rela->r_info;
        }

        struct hookeye_plt_entry *entry = &target->entries[index];
        entry->slot_address = hookeye_adjust_vaddr(target, r_offset);
        entry->relocation_type = ELF64_R_TYPE(r_info);
        entry->symbol_index = ELF64_R_SYM(r_info);
        entry->symbol_name = hookeye_symbol_name(target, entry->symbol_index);

        enum hookeye_status status = hookeye_read_exact(
            target,
            entry->slot_address,
            &entry->jump_address,
            sizeof(entry->jump_address));
        if (status != HOOKEYE_OK) {
            return status;
        }

        entry->module_base = hookeye_memory_map_module_base(&target->maps, entry->jump_address);
        entry->module_name = hookeye_memory_map_module_name(&target->maps, entry->module_base);
        entry->resolved = !hookeye_address_in_main_image(target, entry->jump_address);
    }

    return HOOKEYE_OK;
}

enum hookeye_status hookeye_parse_remote_elf(struct hookeye_target *target) {
    const struct hookeye_memory_region *base_region = hookeye_find_main_base_region(target);
    if (base_region == NULL) {
        return HOOKEYE_ERR_IO;
    }

    enum hookeye_status status = hookeye_read_program_headers(target, base_region->start);
    if (status != HOOKEYE_OK) {
        return status;
    }

    status = hookeye_compute_load_bias(target);
    if (status != HOOKEYE_OK) {
        return status;
    }

    struct hookeye_dynamic_info info;
    status = hookeye_parse_dynamic_info(target, &info);
    if (status != HOOKEYE_OK) {
        return status;
    }

    status = hookeye_read_symbols_and_strings(target, &info);
    if (status != HOOKEYE_OK) {
        return status;
    }

    status = hookeye_read_jmprel(target, &info);
    if (status != HOOKEYE_OK) {
        return status;
    }

    return hookeye_build_plt_entries(target);
}

const char *hookeye_relocation_name(uint32_t reloc_type) {
    switch (reloc_type) {
        case R_X86_64_JUMP_SLOT:
            return "JUMP_SLOT";
        case R_X86_64_GLOB_DAT:
            return "GLOB_DAT";
        case R_X86_64_64:
            return "ABS64";
        case R_X86_64_RELATIVE:
            return "RELATIVE";
        default:
            return "OTHER";
    }
}

const char *hookeye_status_string(enum hookeye_status status) {
    switch (status) {
        case HOOKEYE_OK:
            return "ok";
        case HOOKEYE_ERR_ARGUMENT:
            return "invalid argument";
        case HOOKEYE_ERR_IO:
            return "I/O failure";
        case HOOKEYE_ERR_NOMEM:
            return "out of memory";
        case HOOKEYE_ERR_PTRACE:
            return "ptrace failure";
        case HOOKEYE_ERR_ELF:
            return "ELF parse failure";
        case HOOKEYE_ERR_UNSUPPORTED:
            return "unsupported ELF configuration";
        default:
            return "unknown error";
    }
}

enum hookeye_status hookeye_target_open(struct hookeye_target *target, pid_t pid) {
    if (target == NULL || pid <= 0) {
        return HOOKEYE_ERR_ARGUMENT;
    }

    memset(target, 0, sizeof(*target));
    target->pid = pid;

    enum hookeye_status status = hookeye_procfs_read_exe_path(pid, target->exe_path, sizeof(target->exe_path));
    if (status != HOOKEYE_OK) {
        return status;
    }

    status = hookeye_procfs_parse_maps(pid, &target->maps);
    if (status != HOOKEYE_OK) {
        hookeye_target_close(target);
        return status;
    }

    status = hookeye_ptrace_attach(target);
    if (status != HOOKEYE_OK) {
        hookeye_target_close(target);
        return status;
    }

    status = hookeye_parse_remote_elf(target);
    if (status != HOOKEYE_OK) {
        hookeye_target_close(target);
        return status;
    }

    return HOOKEYE_OK;
}

void hookeye_target_close(struct hookeye_target *target) {
    if (target == NULL) {
        return;
    }

    hookeye_ptrace_detach(target);
    hookeye_memory_map_free(&target->maps);
    free(target->phdrs);
    free(target->dynamic_entries);
    free(target->symtab);
    free(target->strtab);
    free(target->jmprel);
    free(target->entries);
    memset(target, 0, sizeof(*target));
}

void hookeye_target_dump(FILE *stream, const struct hookeye_target *target) {
    fprintf(stream,
            "pid=%ld exe=%s load_bias=0x%" PRIxPTR " image=[0x%" PRIxPTR ",0x%" PRIxPTR ")\n",
            (long)target->pid,
            target->exe_path,
            target->load_bias,
            target->image_start,
            target->image_end);

    for (size_t index = 0; index < target->entry_count; ++index) {
        const struct hookeye_plt_entry *entry = &target->entries[index];
        fprintf(stream,
                "[%03zu] slot=0x%" PRIxPTR " target=0x%" PRIxPTR " rel=%s sym=%s module=%s state=%s\n",
                index,
                entry->slot_address,
                entry->jump_address,
                hookeye_relocation_name(entry->relocation_type),
                (entry->symbol_name != NULL) ? entry->symbol_name : "?",
                (entry->module_name != NULL) ? entry->module_name : "?",
                entry->resolved ? "resolved" : "lazy");
    }
}
