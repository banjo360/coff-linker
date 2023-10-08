# coff-linker

Patches the relative offsets an .OBJ file (e.g. jumps) and extracts .text/.data sections.

For now, uses the function's name to know its memory address. Functions have to be named `FUN_<address in hex>` (i.e. `FUN_8045dc14`).