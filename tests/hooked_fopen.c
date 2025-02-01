#include <stdio.h>

FILE *fopen(const char *path, const char *mode) {
    printf("hooked fopen()\n");
    return NULL;
}