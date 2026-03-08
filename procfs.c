#include "hookeye_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void hookeye_memory_region_reset(struct hookeye_memory_region *region) {
    if (region == NULL) {
        return;
    }

    free(region->path);
    free(region->module);
    memset(region, 0, sizeof(*region));
}

static char *hookeye_strdup_trimmed(const char *text) {
    if (text == NULL) {
        return NULL;
    }

    while (*text == ' ') {
        ++text;
    }

    size_t length = strlen(text);
    while (length > 0 && (text[length - 1] == '\n' || text[length - 1] == '\r')) {
        --length;
    }

    char *copy = malloc(length + 1U);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, text, length);
    copy[length] = '\0';
    return copy;
}

static char *hookeye_module_name_from_path(const char *path) {
    if (path == NULL || *path == '\0' || *path == '[') {
        return NULL;
    }

    const char *base = strrchr(path, '/');
    base = (base == NULL) ? path : base + 1;
    return strdup(base);
}

static enum hookeye_status hookeye_parse_maps_line(
    const char *line,
    struct hookeye_memory_region *region) {
    unsigned long start = 0;
    unsigned long end = 0;
    unsigned long long offset = 0;
    unsigned long inode = 0;
    int consumed = 0;
    int parsed = sscanf(line,
                        "%lx-%lx %4s %llx %15s %lu %n",
                        &start,
                        &end,
                        region->perms,
                        &offset,
                        region->dev,
                        &inode,
                        &consumed);
    if (parsed < 6) {
        return HOOKEYE_ERR_IO;
    }

    memset(region, 0, sizeof(*region));
    region->start = (uintptr_t)start;
    region->end = (uintptr_t)end;
    region->offset = (uint64_t)offset;
    region->inode = inode;

    if (line[consumed] != '\0') {
        region->path = hookeye_strdup_trimmed(line + consumed);
        if (region->path == NULL) {
            return HOOKEYE_ERR_NOMEM;
        }
        if (*region->path != '\0') {
            region->module = hookeye_module_name_from_path(region->path);
            if (region->module == NULL && region->path[0] != '[') {
                hookeye_memory_region_reset(region);
                return HOOKEYE_ERR_NOMEM;
            }
        }
    }

    return HOOKEYE_OK;
}

enum hookeye_status hookeye_procfs_read_exe_path(pid_t pid, char *buffer, size_t size) {
    if (buffer == NULL || size == 0U || pid <= 0) {
        return HOOKEYE_ERR_ARGUMENT;
    }

    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%ld/exe", (long)pid);

    ssize_t length = readlink(link_path, buffer, size - 1U);
    if (length < 0) {
        return HOOKEYE_ERR_IO;
    }

    buffer[length] = '\0';
    return HOOKEYE_OK;
}

enum hookeye_status hookeye_procfs_parse_maps(pid_t pid, struct hookeye_memory_map *map) {
    if (pid <= 0 || map == NULL) {
        return HOOKEYE_ERR_ARGUMENT;
    }

    memset(map, 0, sizeof(*map));

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/maps", (long)pid);

    FILE *stream = fopen(path, "re");
    if (stream == NULL) {
        return HOOKEYE_ERR_IO;
    }

    enum hookeye_status status = HOOKEYE_OK;
    char *line = NULL;
    size_t line_capacity = 0;
    struct hookeye_memory_region *regions = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (;;) {
        errno = 0;
        ssize_t length = getline(&line, &line_capacity, stream);
        if (length < 0) {
            if (feof(stream) != 0) {
                break;
            }
            status = HOOKEYE_ERR_IO;
            goto cleanup;
        }

        if (capacity == count) {
            size_t next_capacity = (capacity == 0U) ? 32U : capacity * 2U;
            void *grown = reallocarray(regions, next_capacity, sizeof(*regions));
            if (grown == NULL) {
                status = HOOKEYE_ERR_NOMEM;
                goto cleanup;
            }
            regions = grown;
            capacity = next_capacity;
        }

        status = hookeye_parse_maps_line(line, &regions[count]);
        if (status != HOOKEYE_OK) {
            goto cleanup;
        }
        ++count;
    }

    if (count == 0U) {
        status = HOOKEYE_ERR_IO;
        goto cleanup;
    }

    map->regions = regions;
    map->count = count;

cleanup:
    if (status != HOOKEYE_OK) {
        for (size_t index = 0; index < count; ++index) {
            hookeye_memory_region_reset(&regions[index]);
        }
        free(regions);
    }
    free(line);
    fclose(stream);
    return status;
}

void hookeye_memory_map_free(struct hookeye_memory_map *map) {
    if (map == NULL) {
        return;
    }

    for (size_t index = 0; index < map->count; ++index) {
        hookeye_memory_region_reset(&map->regions[index]);
    }
    free(map->regions);
    map->regions = NULL;
    map->count = 0;
}

const struct hookeye_memory_region *hookeye_memory_map_find_region(
    const struct hookeye_memory_map *map,
    uintptr_t address) {
    if (map == NULL) {
        return NULL;
    }

    for (size_t index = 0; index < map->count; ++index) {
        const struct hookeye_memory_region *region = &map->regions[index];
        if (region->start <= address && address < region->end) {
            return region;
        }
    }

    return NULL;
}

const struct hookeye_memory_region *hookeye_memory_map_find_file_region(
    const struct hookeye_memory_map *map,
    const char *path,
    uint64_t offset) {
    if (map == NULL || path == NULL) {
        return NULL;
    }

    for (size_t index = 0; index < map->count; ++index) {
        const struct hookeye_memory_region *region = &map->regions[index];
        if (region->path != NULL && strcmp(region->path, path) == 0 && region->offset == offset) {
            return region;
        }
    }

    return NULL;
}

uintptr_t hookeye_memory_map_module_base(
    const struct hookeye_memory_map *map,
    uintptr_t address) {
    const struct hookeye_memory_region *region = hookeye_memory_map_find_region(map, address);
    if (region == NULL) {
        return 0U;
    }

    if (region->path == NULL || region->inode == 0UL) {
        return region->start;
    }

    for (size_t index = 0; index < map->count; ++index) {
        const struct hookeye_memory_region *candidate = &map->regions[index];
        if (candidate->inode == region->inode &&
            strcmp(candidate->dev, region->dev) == 0 &&
            candidate->path != NULL &&
            strcmp(candidate->path, region->path) == 0) {
            return candidate->start;
        }
    }

    return region->start;
}

const char *hookeye_memory_map_module_name(
    const struct hookeye_memory_map *map,
    uintptr_t base) {
    if (map == NULL || base == 0U) {
        return NULL;
    }

    for (size_t index = 0; index < map->count; ++index) {
        const struct hookeye_memory_region *region = &map->regions[index];
        if (region->start == base) {
            if (region->module != NULL) {
                return region->module;
            }
            return region->path;
        }
    }

    return NULL;
}
