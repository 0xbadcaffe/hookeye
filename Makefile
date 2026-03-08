CC ?= cc

CFLAGS ?= -O3 -g
CFLAGS += -std=c2x -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
LDFLAGS ?=

OBJ = hookeye.o procfs.o ptrace_io.o elf_inspect.o

.PHONY: all clean

all: hookeye

hookeye: $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

clean:
	rm -f $(OBJ) hookeye
