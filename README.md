# hookeye

Linux ELF runtime hook inspector. `hookeye` examines a live process and reports where its PLT/GOT entries resolve, helping identify redirected imports and unexpected modules.

## Features

- Parses `/proc/<pid>/maps` and the in-memory ELF `PT_DYNAMIC` segment
- Resolves `.dynsym`, `.dynstr`, and `DT_JMPREL` entries
- Supports `DT_SYMTABSZ`, `DT_HASH`, and `DT_GNU_HASH`
- Reports each slot, target address, symbol, module, relocation type, and resolution state

## Build

```sh
make
```

Requires Linux and a C23-capable compiler.

## Usage

```sh
./hookeye <pid>
./hookeye --self
```

Inspecting another process requires sufficient `ptrace` permissions.

## Design

- [`hookeye.c`](https://github.com/0xbadcaffe/hookeye/blob/master/hookeye.c): CLI
- [`procfs.c`](https://github.com/0xbadcaffe/hookeye/blob/master/procfs.c): process mappings
- [`ptrace_io.c`](https://github.com/0xbadcaffe/hookeye/blob/master/ptrace_io.c): remote memory access
- [`elf_inspect.c`](https://github.com/0xbadcaffe/hookeye/blob/master/elf_inspect.c): ELF inspection

## Limitations

- Linux and 64-bit ELF only
- Detects PLT/GOT redirection, not inline code hooks
- Reports state at inspection time; temporary hooks may evade a single snapshot

## References

- [System V ABI ELF gABI](https://gabi.xinuos.com/elf/)
- [Program loading and base addresses](https://gabi.xinuos.com/elf/07-pheader.html)
- [Dynamic section](https://gabi.xinuos.com/elf/08-dynamic.html)

## License

[MIT](LICENSE)
