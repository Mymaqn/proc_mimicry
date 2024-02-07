#define _GNU_SOURCE
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "proc_maps.h"

void hide(char *bin_name);

static void **unmap_orig_exe_mappings(char *bin_name, maps_t_arr *mappings) {
    void **new_mappings = malloc((mappings->size + 1) * 8);
    for (size_t i = 0; i < mappings->size; i++) {
        maps_t mapping = mappings->maps[i];
        if (strcmp(bin_name, mapping.file_path) == 0) {
            size_t size = mapping.addr_end - mapping.addr_start;
            new_mappings[i] = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

            if (new_mappings[i] == MAP_FAILED) {
                abort();
            }
            memcpy(new_mappings[i], (void *)mapping.addr_start, size);
            if (munmap((void *)mapping.addr_start, size) != 0) {
                abort();
            }
        }
    }
    return new_mappings;
}

static void remap_exe(const char *bin_name, void **orig_mappings, maps_t_arr *mappings) {
    for (size_t i = 0; i < mappings->size; i++) {
        maps_t mapping = mappings->maps[i];
        if (strcmp(bin_name, mapping.file_path) == 0) {
            size_t size = mapping.addr_end - mapping.addr_start;

            if (mmap((void *)mapping.addr_start, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
                abort();
            }
            memcpy((void *)mapping.addr_start, orig_mappings[i], size);
            mprotect((void *)mapping.addr_start, size, mapping.mode);
            if (munmap((void *)orig_mappings[i], size) != 0) {
                abort();
            }
        }
    }
}

// Need this because unmapping the original binary will fuck with symbol resolution
// We are using pragma's to ignore this function during compilation, as we know they are failing beforehand
#pragma GCC diagnostic ignored "-Wnonnull"
#pragma GCC diagnostic ignored "-Wunused-variable"
static void load_needed_funcs() {
    int fd = open(NULL, O_RDONLY);
    prctl(-1, -1, -1, -1, -1);
    mprotect(NULL, -1, -1);
}
#pragma GCC diagnostic pop

static int change_proc_exe(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        abort();
    }
    int success = prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0);
    if (success != 0) {
        abort();
    }
    return fd;
}

// Following two functions were taken from:
// https://stackoverflow.com/questions/64406468/change-executable-file-name-via-prctl-in-linux
// And slightly modified
static int change_name(const char *name) {
    int ret = prctl(PR_SET_NAME, name);
    if (ret < 0) {
        abort();
    }

    return 0;
}

struct prctl_mm_map *get_mm_map() {
    FILE *f = NULL;
    int i, fd;
    char *buf_ptr;
    char buf[4096];
    int ret = 0;
    ssize_t bytes_read = 0;

    /*
     * We don't really need to know all of this stuff, but unfortunately
     * PR_SET_MM_MAP requires us to set it all at once, so we have to
     * figure it out anyway.
     */
    unsigned long start_data, end_data, start_brk, start_code, end_code,
        start_stack, arg_start, arg_end, env_start, env_end, brk_val;
    struct prctl_mm_map *prctl_map;

    f = fopen("/proc/self/stat", "r");
    if (!f) {
        abort();
    }

    fd = fileno(f);
    if (fd < 0) {
        fclose(f);
        abort();
    }

    bytes_read = read(fd, buf, sizeof(buf) - 1);
    if (bytes_read <= 0) {
        fclose(f);
        abort();
    }

    buf[bytes_read] = '\0';

    /* Skip the first 25 fields, column 26-28 are start_code, end_code,
     * and start_stack */
    buf_ptr = strchr(buf, ' ');
    for (i = 0; i < 24; i++) {
        if (!buf_ptr) {
            fclose(f);
            abort();
        }
        buf_ptr = strchr(buf_ptr + 1, ' ');
    }
    if (!buf_ptr) {
        fclose(f);
        abort();
    }

    i = sscanf(buf_ptr, "%lu %lu %lu", &start_code, &end_code, &start_stack);
    if (i != 3) {
        fclose(f);
        abort();
    }

    /* Skip the next 19 fields, column 45-51 are start_data to arg_end */
    for (i = 0; i < 19; i++) {
        if (!buf_ptr) {
            fclose(f);
            abort();
        }
        buf_ptr = strchr(buf_ptr + 1, ' ');
    }

    if (!buf_ptr) {
        fclose(f);
        abort();
    }

    i = sscanf(buf_ptr, "%lu %lu %lu %lu %lu %lu %lu",
               &start_data, &end_data, &start_brk, &arg_start, &arg_end, &env_start, &env_end);
    if (i != 7) {
        fclose(f);
        abort();
    }

    /* Include the null byte here, because in the calculations below we
     * want to have room for it. */

    brk_val = syscall(12, 0);

    prctl_map = malloc(sizeof(struct prctl_mm_map) + 1);
    if (prctl_map == NULL) {
        return NULL;
    }

    prctl_map->start_code = start_code;
    prctl_map->end_code = end_code;
    prctl_map->start_stack = start_stack;
    prctl_map->start_data = start_data;
    prctl_map->end_data = end_data;
    prctl_map->start_brk = start_brk;
    prctl_map->brk = brk_val;
    prctl_map->arg_start = arg_start;
    prctl_map->arg_end = arg_end;
    prctl_map->env_start = env_start;
    prctl_map->env_end = env_end;
    prctl_map->auxv = NULL;
    prctl_map->auxv_size = 0;
    prctl_map->exe_fd = -1;

    ret = prctl(PR_SET_MM, PR_SET_MM_MAP, prctl_map, sizeof(struct prctl_mm_map), 0);

    if (ret != 0) {
        fclose(f);
        return NULL;
    }
    fclose(f);

    return prctl_map;
}

struct prctl_mm_map *setproctitle(struct prctl_mm_map *prctl_map, char *title) {
    static char *proctitle = NULL;
    char *tmp_proctitle;
    unsigned long arg_start, arg_end;

    int len = strlen(title) + 1;

    tmp_proctitle = realloc(proctitle, len);
    if (!tmp_proctitle) {
        abort();
    }
    proctitle = tmp_proctitle;

    arg_start = (unsigned long)proctitle;
    arg_end = arg_start + len;

    prctl_map->arg_start = arg_start;
    prctl_map->arg_end = arg_end;

    int ret = prctl(PR_SET_MM, PR_SET_MM_MAP, prctl_map, sizeof(struct prctl_mm_map), 0);
    if (ret == 0) {
        strncpy((char *)arg_start, title, len);
    } else {
        abort();
    }
    return prctl_map;
}

void hide(char *new_bin_name) {
    char bin_name[2048];
    memset(bin_name, '\0', 2048);
    struct prctl_mm_map *prctl_map = get_mm_map();
    if (prctl_map == NULL) {
        abort();
    }

    load_needed_funcs();

    readlink("/proc/self/exe", bin_name, 2048);
    maps_t_arr *mappings = parse_maps_from_path("/proc/self/maps");

    void **orig_mappings = unmap_orig_exe_mappings(bin_name, mappings);
    int new_proc = change_proc_exe(new_bin_name);
    remap_exe(bin_name, orig_mappings, mappings);

    free(orig_mappings);
    destroy_maps_t_arr(mappings);

    setproctitle(prctl_map, basename(new_bin_name));
    change_name(basename(new_bin_name));

    close(new_proc);
    return;
}
