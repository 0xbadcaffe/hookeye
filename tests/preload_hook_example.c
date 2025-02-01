#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    printf("Calling the fopen() function\n");

    FILE *fd = fopen("test.txt","r");
    if (!fd) {
        printf("fopen() returned NULL\n");
        for(;;);
        return EXIT_FAILURE;
    }

    printf("fopen() succedded\n");
    return EXIT_SUCCESS;
}