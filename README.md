## evmc

evmc is a simple and compact EsetVM bytecode interpreter and AOT compiler/translator to standalone PE32+ (64-bit) windows executable file.
To learn more about the EsetVM read the [docs](docs/evm.md).

Usage:

- `evmc.exe examples/crc32.evm` to create executable file crc32.evm.exe
- `evmc.exe -i examples/crc32.evm` to only run the program interpreting the bytecode.
