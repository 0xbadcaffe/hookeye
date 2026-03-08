#include "hookeye.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void hookeye_usage(FILE *stream, const char *argv0) {
    fprintf(stream, "usage: %s <pid>\n", argv0);
    fprintf(stream, "       %s --self\n", argv0);
}

static enum hookeye_status hookeye_parse_pid(const char *text, pid_t *pid) {
    if (text == NULL || pid == NULL || *text == '\0') {
        return HOOKEYE_ERR_ARGUMENT;
    }

    errno = 0;
    char *end = NULL;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value <= 0) {
        return HOOKEYE_ERR_ARGUMENT;
    }

    *pid = (pid_t)value;
    return HOOKEYE_OK;
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        hookeye_usage((argc == 2) ? stdout : stderr, argv[0]);
        return (argc == 2) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    pid_t pid = 0;
    enum hookeye_status status = HOOKEYE_OK;
    if (strcmp(argv[1], "--self") == 0) {
        pid = getpid();
    } else {
        status = hookeye_parse_pid(argv[1], &pid);
        if (status != HOOKEYE_OK) {
            fprintf(stderr, "hookeye: %s\n", hookeye_status_string(status));
            return EXIT_FAILURE;
        }
    }

    struct hookeye_target target;
    status = hookeye_target_open(&target, pid);
    if (status != HOOKEYE_OK) {
        fprintf(stderr, "hookeye: pid %ld: %s\n", (long)pid, hookeye_status_string(status));
        return EXIT_FAILURE;
    }

    hookeye_target_dump(stdout, &target);
    hookeye_target_close(&target);
    return EXIT_SUCCESS;
}
