# hookeye

`hookeye` inspects a live Linux process and walks its ELF dynamic linking state to determine what each PLT/GOT slot currently resolves to. The practical goal is hook detection: if a PLT entry for a symbol such as `open`, `fopen`, or `malloc` resolves somewhere unexpected, `hookeye` gives you the raw addresses and module ownership needed to spot it.

## What It Does

- Parses `/proc/<pid>/maps` to understand the target process image layout.
- Attaches to the target when needed and reads remote memory safely.
- Parses the in-memory ELF program headers and `PT_DYNAMIC` segment.
- Resolves `.dynsym`, `.dynstr`, `.got.plt`, and `DT_JMPREL` relocation entries.
- Prints each PLT slot, current jump target, symbol name, relocation type, module name, and resolution state.

## Design

`hookeye` is organized into focused modules:

- [hookeye.c](https://github.com/0xbadcaffe/hookeye/blob/main/hookeye.c): CLI entrypoint
- [procfs.c](https://github.com/0xbadcaffe/hookeye/blob/main/procfs.c): `/proc` map parsing and module lookup
- [ptrace_io.c](https://github.com/0xbadcaffe/hookeye/blob/main/ptrace_io.c): attach/detach and remote memory reads
- [elf_inspect.c](https://github.com/0xbadcaffe/hookeye/blob/main/elf_inspect.c): ELF and dynamic-link inspection
- [hookeye.h](https://github.com/0xbadcaffe/hookeye/blob/main/hookeye.h): public types and APIs
- [hookeye_internal.h](https://github.com/0xbadcaffe/hookeye/blob/main/hookeye_internal.h): internal interfaces and compatibility constants

The ELF handling is designed around current ABI practice:

- Uses load-bias computation from program headers instead of relying on simplistic base assumptions.
- Uses `DT_SYMTABSZ` when present.
- Falls back to `DT_HASH` or `DT_GNU_HASH` to size `.dynsym` on current GNU-linked binaries.
- Enumerates PLT relocation entries from `DT_JMPREL` and `DT_PLTRELSZ`.

## Build

```sh
make
```

Build flags currently target modern C with strong warnings:

```text
-std=c2x -O3 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
```

## Usage

Inspect another process:

```sh
./hookeye <pid>
```

Inspect the current `hookeye` process without ptrace attach:

```sh
./hookeye --self
```

Example output shape:

```text
pid=1616972 exe=/home/.../hookeye load_bias=0x5ae9500ed000 image=[0x5ae9500ed000,0x5ae9500f3050)
[000] slot=0x5ae9500f2ed8 target=0x7ff145049260 rel=JUMP_SLOT sym=getenv module=libc.so.6 state=resolved
```

## Hook Detection Model

At a high level, `hookeye` answers this question:

```text
"For each imported function, where does the process actually jump now?"
```

That matters because GOT/PLT hooks usually work by changing an imported function's effective destination.

Normal flow:

```text
call site
   |
   v
 .plt stub
   |
   v
.got.plt slot  -----------------------> libc.so.6:function
```

Hooked flow:

```text
call site
   |
   v
 .plt stub
   |
   v
.got.plt slot  -----------------------> suspicious module / injected code / trampoline
```

If a slot that should point into `libc.so.6`, `libpthread.so.0`, or another expected shared object instead points into an unknown mapping, anonymous executable memory, or an unexpected library, that is a strong hook signal.

## ELF and PLT/GOT Layout

Process image, simplified:

```text
+---------------------------+
| ELF Header                |
+---------------------------+
| Program Header Table      |
+---------------------------+
| PT_LOAD: text / code      |
|   .init                   |
|   .plt                    |
|   .text                   |
|   .fini                   |
+---------------------------+
| PT_LOAD: rodata           |
|   .rodata                 |
|   .eh_frame               |
+---------------------------+
| PT_LOAD: data             |
|   .dynamic                |
|   .got                    |
|   .got.plt                |
|   .data / .bss            |
+---------------------------+
```

Dynamic linker view:

```text
PT_DYNAMIC
   |
   +--> DT_SYMTAB   ----> .dynsym
   |
   +--> DT_STRTAB   ----> .dynstr
   |
   +--> DT_JMPREL   ----> .rela.plt / .rel.plt
   |
   +--> DT_PLTRELSZ ----> relocation table size
   |
   +--> DT_PLTREL   ----> RELA or REL
   |
   +--> DT_PLTGOT   ----> .got.plt
```

PLT/GOT relationship:

```text
                imported call: printf()

    caller
      |
      v
  +---------+        jumps through        +----------------+
  |  .plt   | --------------------------> |   .got.plt     |
  | stub N  |                             | slot for printf|
  +---------+                             +----------------+
                                                  |
                                                  v
                                 +----------------------------------+
                                 | current resolved target address  |
                                 +----------------------------------+
                                                  |
                                                  v
                                  libc.so.6:printf   or   hook code
```

Relocation record to GOT slot:

```text
DT_JMPREL entry

    r_offset  ---> address of GOT/PLT slot to patch
    r_info    ---> symbol index + relocation type
                    |               |
                    |               +--> e.g. R_X86_64_JUMP_SLOT
                    |
                    +--> .dynsym[index]
                              |
                              +--> st_name -> .dynstr -> "printf"
```

What `hookeye` reconstructs:

```text
symbol name  -> GOT slot -> current pointer -> owning module -> resolved/lazy state
```

## Why This Matters For Hook Checks

Common user-space hook patterns include:

- PLT/GOT slot rewriting
- preload-based interposition
- trampolines into injected shared libraries
- redirection into anonymous executable mappings

`hookeye` is built to surface those outcomes directly instead of guessing from disk ELF state alone.

## Current Limitations

- Linux-specific
- 64-bit ELF only
- Focused on dynamic-link state and PLT/GOT resolution, not inline patch disassembly
- External process inspection depends on ptrace policy, capabilities, and kernel settings

## Next Version Feature List

The current implementation is strongest against hooks that are visible in PLT/GOT state at the moment the target is stopped and inspected. A more advanced attacker can still try to evade that view, so the next version should expand coverage in these areas:

- Inline hook detection for imported functions and critical libc entrypoints, to catch code-patching attacks that do not touch `.got.plt`
- Trampoline detection in executable anonymous mappings, to catch jumps into injected code caves or manually mapped payloads
- Expected-module validation, to flag cases where a symbol resolves to a plausible shared object name but lands outside the expected code range
- Pre-attach and post-attach comparison modes, to help identify targets that temporarily restore clean GOT state before inspection
- Mapping anomaly detection for short-lived executable pages, suspicious `memfd` mappings, and unusual `rwx` regions
- Thread-aware inspection, to help catch per-thread or race-window hook behavior that may not show up in a single narrow snapshot
- Optional prologue fingerprinting against on-disk ELF data, to catch tampering inside otherwise legitimate modules such as `libc.so.6`
- Loader and environment checks for interposition signals such as suspicious preload usage, unexpected linker state, or modified runtime search paths

## Specification Sources Used

Primary ELF references used for the refactor:

- System V ABI ELF gABI draft 4.3, September 4, 2025:
  https://gabi.xinuos.com/elf/
- Program loading and base-address computation:
  https://gabi.xinuos.com/elf/07-pheader.html
- Dynamic section tags and semantics, including `DT_SYMTABSZ`, `DT_SYMTAB`, `DT_STRTAB`, `DT_JMPREL`, `DT_PLTRELSZ`, and `DT_PLTREL`:
  https://gabi.xinuos.com/elf/08-dynamic.html

Relevant practical GNU reality also influenced compatibility behavior:

- Many current Linux binaries expose `DT_GNU_HASH` without `DT_HASH`.
- Current system headers may not yet define newer dynamic tags such as `DT_SYMTABSZ`, so compatibility defines are included where needed.
