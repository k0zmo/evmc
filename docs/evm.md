# EVM

## Architecture

EVM has Harvard architecture and consist of:

- 32 signed 64-bit registers (`r0..r31`),
- linear memory addressed from `0x0`,
- call stack (used by `call` and `ret` instructions).

## Arithemtic

Arithemtic operations use two's complement representation.

## Instruction Set

Instructions are placed in a consecutive block of memory, addressed from `0x0`.

Execution starts at instruction 0, after every instruction "instruction pointer" (`ip`) is incremented. Jump instructions might affect `ip`.

Every instruction is 3 bytes long, most instructions have format:

| Op-code  | Destination  | Source  |
|:--------:|:------------:|:-------:|
|  8 bits  |    8 bits    | 8 bits  |

or, instruction taking argument imm16 have format

| Op-code  | Argument |
|:--------:|:--------:|
|  8 bits  | 16 bits  |

Available instructions:

| Instruction    | Op-Code | Description                                                                                              |       Pseudo-code        |
|:--------------:|:-------:|:---------------------------------------------------------------------------------------------------------|:------------------------:|
| `nop`          | 32      | no operation                                                                                             |                          |
| `in r0`        | 40      | read hexadecimal value from standard input and store it in the registry `r0`                             | `r0 <- stdin`            |
| `out r0`       | 41      | write hexadecimal value in registry `r0` to standard output                                              | `stdout <- r0`           |
| `store r0, r1` | 48      | store value of `r1` in memory addressed by `r0`                                                          | `[r0] = r1`              |
| `load r0, r1`  | 49      | load value from memory addressed by `r1` into register `r0`                                              | `r0 = [r1]`              |
| `ldc r0, imm8` | 50      | load 8-bit immediate value to `r0`                                                                       | `r0 = imm8`              |
| `mov r0, r1`   | 64      | copy value from `r1` to `r0`                                                                             | `r0 = r1`                |
| `add r0, r1`   | 65      | add value of `r1` to `r0`, saving the result in `r0`                                                     | `r0 += r1`               |
| `sub r0, r1`   | 66      | subtract value of `r1` from `r0`, saving the result in `r0`                                              | `r0 -= r1`               |
| `mul r0, r1`   | 67      | multiply value of `r1` by `r0`, saving the result in `r0`                                                | `r0 *= r1`               |
| `div r0, r1`   | 68      | divide value of `r0` by `r1`, saving the result in `r0`                                                  | `r0 /= r1`               |
| `mod r0, r1`   | 69      | calculate a reminder of a division of `r0` by `r1`, saving the result in `r0`                            | `r0 %= r1`               |
| `jz r0, imm8`  | 97      | jump relatively by `imm8` only if value of `r0` is equal to zero                                         | `if r0 == 0: ip += imm8` |
| `jl r0, imm8`  | 98      | jump relatively by `imm8` only if value of `r0` is less then zero                                        | `if r0  < 0: ip += imm8` |
| `jump imm16`   | 99      | jump relatively by `imm16`                                                                               | `ip += imm16`            |
| `call imm16`   | 100     | store next instruction address on internal call stack and jump by `imm16`                                | `push ip, jump imm16`    |
| `ret`          | 101     | reads absolute `ip` from stack and jumps to it, returning to next instruction after corresponding `call` | `ip = pop ip`            |
| `hlt`          | 126     | terminate program execution                                                                              |                          |

## Memory

Memory is linear, addressing starts from 0. Memory has byte-level addressing.
Instructions accessing memory, always access 64-bit values.
Data in stored and read from memory in little-endian format.

### Example

Let's assume we have following bytes in memory:

`0xAA 0xBB 0xCC 0xDD 0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88 0x99 0x00 0xEE 0xFF`

The following program 

```
ldc r0, 1
load r1, r0
```

will load value of `0x5544332211DDCCBB` into register `r1`

# EVM file format

File format consists of three segments: header, code section and initial data section values.

## Header

Header consist of 8 byte magic value "ESET-VM1" followed by 3 32-bit values: size of code (in instructions), size of whole data section (in bytes) and size of initialized data size (in bytes) and can be described using C structure like:

```
struct header
{
    char magic[8];
    uint32_t code_size;
    uint32_t data_size;
    uint32_t initial_data_size;
};
```

All values in header are stored in little endian.

Valid file format has:

- `data_size` >= `initial_data_size`
- `magic == "ESET-VM1"`
- `code_size * 3 + initial_data_size + 20 == size of file`

## Code

After header, instruction block follow. Exactly `code_size` instructions are specified, giving this section `3 * code_size` bytes length.

Each instruction starts with opcode byte (see "Opcode" column in instruction table).
Two bytes follow and their interpretation depends on the argument type:

- Register reference (`rN` in table) is stored as single byte where 0 marks first register and 31 last. Any value above 31 is invalid.
- Immediate (`imm8`) is stored as single byte.
- Long immediate (`imm16`) is stored as two consecutive bytes in little endian.

For example `ldc r5, 33` will be encoded as `0x32 0x05 0x21`.

Some instructions might NOT use argument bytes (i.e `out`), in such case excessive byte(s) are ignored.

## Data section

Data section may be initialized with data loaded from file.
If `initial_data_size > 0`, then `initial_data_size` bytes are read from file and copied to the beginning of the memory.
 Any non-initialized data (`data_size - initial_data_size` bytes) is then initialized to zero.

## Jump encoding

Jump/call target offset is always decoded as relative to current instruction pointer.
Immediate of jump instruction is interpreted as signed integer of proper size (signed char or signed short) and added to next instruction pointer to get target instruction pointer.

- Given absolute jump at 4th instruction, jumping to 5th instruction, it will be encoded as `0x63 0x00 0x00`.
- Given absolute jump at 4th instruction, jumping to 6th instruction, it will be encoded as `0x63 0x01 0x00`.
- Given absolute jump at 4th instruction, jumping to 4th instruction (looping in place), it will be encoded as `0x63 0xFF 0xFF`.
- Given absolute jump at 4th instruction, jumping to 3th instruction, it will be encoded as `0x63 0xFE 0xFF`
