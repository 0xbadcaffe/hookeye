#ifndef HOOKEYE_INTERNAL_H
#define HOOKEYE_INTERNAL_H

#include "hookeye.h"

#ifndef DT_SYMTABSZ
#define DT_SYMTABSZ 39
#endif

#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

enum hookeye_status hookeye_procfs_read_exe_path(pid_t pid, char *buffer, size_t size);
enum hookeye_status hookeye_procfs_parse_maps(pid_t pid, struct hookeye_memory_map *map);
void hookeye_memory_map_free(struct hookeye_memory_map *map);
const struct hookeye_memory_region *hookeye_memory_map_find_region(
    const struct hookeye_memory_map *map, uintptr_t address);
const struct hookeye_memory_region *hookeye_memory_map_find_file_region(
    const struct hookeye_memory_map *map,
    const char *path,
    uint64_t offset);
uintptr_t hookeye_memory_map_module_base(
    const struct hookeye_memory_map *map,
    uintptr_t address);
const char *hookeye_memory_map_module_name(
    const struct hookeye_memory_map *map,
    uintptr_t base);

enum hookeye_status hookeye_ptrace_attach(struct hookeye_target *target);
void hookeye_ptrace_detach(struct hookeye_target *target);
enum hookeye_status hookeye_remote_read(
    const struct hookeye_target *target,
    uintptr_t remote_address,
    void *buffer,
    size_t size);

enum hookeye_status hookeye_parse_remote_elf(struct hookeye_target *target);
const char *hookeye_relocation_name(uint32_t reloc_type);

#endif
