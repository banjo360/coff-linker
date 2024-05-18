# coff-linker

Patches the relative offsets of an .OBJ file (e.g. jumps) and extracts .text/.data/.rdata/.bss sections.

To know the address of the symbols, you need to pass a file containing the mapping. `coff-linker -a addresses.txt`: [example](https://github.com/banjo360/bk360/blob/main/addresses.txt).
