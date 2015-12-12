#pragma once

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iosfwd>
#include <memory>
#include <new>
#include <numeric>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using byte = std::uint8_t;
using word = std::uint16_t;
using dword = std::uint32_t;
using qword = std::uint64_t;
using std::begin;
using std::end;
using std::vector;
using std::string;
using std::unique_ptr;
using std::pair;

constexpr inline byte operator"" _b(unsigned long long i)
{
    return static_cast<byte>(i);
}

constexpr dword align(dword addr, dword alignment)
{
    return (addr + (alignment - 1)) & ~(alignment - 1);
}

template <typename Enum, class = std::enable_if_t<std::is_enum<Enum>::value>>
constexpr auto underlying_cast(Enum e)
{
    return static_cast<std::underlying_type_t<Enum>>(e);
}

template <typename T,
          class = std::enable_if_t<std::is_standard_layout<T>::value>>
inline void write_bytes(std::ostream& os, const T& t)
{
    os.write(reinterpret_cast<const char*>(&t), sizeof(t));
}

template <typename T,
          class = std::enable_if_t<std::is_standard_layout<T>::value>>
inline void read_bytes(std::istream& os, T& t)
{
    os.read(reinterpret_cast<char*>(&t), sizeof(t));
}

struct evm_header
{
    byte magic[8];
    dword code_size;
    dword data_size;
    dword initial_data_size;
};

enum class opcode : byte
{
    nop = 32,
    in = 40,
    out = 41,
    store = 48,
    load = 49,
    ldc = 50,
    mov = 64,
    add = 65,
    sub = 66,
    mul = 67,
    div = 68,
    mod = 69,
    jz = 97,
    jl = 98,
    jump = 99,
    call = 100,
    ret = 101,
    hlt = 126
};
enum { NUM_REGISTERS = 32 };

#pragma pack(push, 1)
struct bytecode_instr
{
    opcode op;
    byte dst;
    byte src;
};
#pragma pack(pop)
static_assert(sizeof(bytecode_instr) == 3, "");

int16_t inline imm16(const bytecode_instr& i)
{
    return static_cast<int16_t>((i.src << 8) | i.dst);
}

std::ostream& operator<<(std::ostream& os, const bytecode_instr& i);
std::ostream& operator<<(std::ostream& os, const vector<bytecode_instr>& is);

dword inline incr_check_overflow(dword base, dword offset)
{
    if (base + offset < base)
        throw std::runtime_error{"address overflow"};
    return base + offset;
}

dword inline incr_check_overflow(dword base, qword offset)
{
    const auto ret = base + offset;
    if (ret < base || ret > (qword)0xFFFFFFFF)
        throw std::runtime_error{"address overflow"};
    return static_cast<dword>(ret);
}

dword inline decr_check_overflow(dword base, dword offset)
{
    if (base - offset > base)
        throw std::runtime_error{"address overflow"};
    return base - offset;
}
