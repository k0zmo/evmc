#include "codegen.h"
#include "data_symbols.h"
#include "import_symbols.h"

/*
  Following codegen uses RIP-relative addressing thus imagebase can be +2GB. It
  also assumes small code model - the program and its symbols must be linked in
  the lower 2 GB of the address space.
 */

void label_symbols::add(std::string name, dword size)
{
    check_duplicates(name);
    labels_.emplace_back(std::move(name), current_offset_);
    current_offset_ = incr_check_overflow(current_offset_, size);
}

void label_symbols::add(dword addr)
{
    n_labels_.push_back(current_offset_);
    current_offset_ = incr_check_overflow(current_offset_, addr);
}

dword label_symbols::symbols(const char* name) const
{
    const auto needle =
        std::find_if(begin(labels_), end(labels_),
                     [&](const auto& sym) { return sym.first == name; });
    if (needle == end(labels_))
        throw std::runtime_error{"Error: Jump address out of bounds"};
    return needle->second;
}

dword label_symbols::symbols(size_t idx) const
{
    if (idx >= n_labels_.size())
        throw std::runtime_error{"Error: Jump address out of bounds"};
    return n_labels_[idx];
}

void label_symbols::set_rva(dword rva)
{
    for (auto& l : labels_)
        l.second = incr_check_overflow(l.second, rva);
    for (auto& l : n_labels_)
        l = incr_check_overflow(l, rva);
}

void label_symbols::check_duplicates(const std::string& label_name)
{
    const auto needle =
        std::find_if(begin(labels_), end(labels_),
                     [&](const auto& sym) { return sym.first == label_name; });
    if (needle != end(labels_))
        throw std::runtime_error{"label with given name alread added"};
}

struct rip_relative
{
    explicit rip_relative(dword symb_addr) : symb_addr{symb_addr} {}
    dword symb_addr;
};

machine_code_writer& machine_code_writer::operator<<(byte b)
{
    strm_ << b;
    return *this;
}

machine_code_writer& machine_code_writer::operator<<(dword addr)
{
    write_bytes(strm_, addr);
    return *this;
}

machine_code_writer& machine_code_writer::operator<<(rip_relative abs)
{
    const auto rip = incr_check_overflow(
        code_rva_, static_cast<size_t>(strm_.tellp()) + sizeof(dword));

    if (rip > abs.symb_addr && (rip - abs.symb_addr) > (dword)0x7FFFFFFF)
        throw std::runtime_error{"code/data to big"};
    else if (rip < abs.symb_addr && (abs.symb_addr - rip) > (dword)0x7FFFFFF)
        throw std::runtime_error{"code/data to big"};

    const auto rel_addr = abs.symb_addr - rip;
    write_bytes(strm_, rel_addr);
    return *this;
}

vector<byte> machine_code_writer::get() const
{
    auto str = strm_.str();
    return {begin(str), end(str)};
}

namespace {
// Following: http://ref.x86asm.net/coder64.html#modrm_byte_32_64
enum class displacement_type
{
    no_disp,
    disp_8,
    disp_32
};

dword displacement_size(displacement_type d)
{
    switch (d)
    {
    case displacement_type::no_disp:
        return 0;
    case displacement_type::disp_8:
        return sizeof(byte);
    case displacement_type::disp_32:
        return sizeof(dword);
    }
    return 0;
}

displacement_type reg_displacement(byte reg)
{
    if (reg == 0)
        return displacement_type::no_disp;
    else if (reg > 0 && reg <= 15)
        return displacement_type::disp_8;
    else
        return displacement_type::disp_32;
}

dword reg_displacement_size(byte reg)
{
    // include one for ModRM byte
    return displacement_size(reg_displacement(reg)) + 1;
}

void validate_register(byte reg)
{
    if (reg >= NUM_REGISTERS)
        throw std::runtime_error{
            "Error: Instruction register index out of bounds"};
}
}

template <byte BaseDisp>
struct displacement
{
    explicit displacement(byte reg) : reg{reg} {}
    const byte reg;

    friend machine_code_writer& operator<<(machine_code_writer& writer,
                                           displacement disp)
    {
        switch (reg_displacement(disp.reg))
        {
        case displacement_type::no_disp:
            writer << BaseDisp;
            break;
        case displacement_type::disp_8:
            writer << static_cast<byte>(BaseDisp + 0x40_b)
                   << static_cast<byte>(disp.reg * 8);
            break;
        case displacement_type::disp_32:
            writer << static_cast<byte>(BaseDisp + 0x80_b)
                   << static_cast<dword>(disp.reg * 8);
            break;
        }
        return writer;
    }
};

/*
  At the beginning of the program we have a unaligned stack (at 16 byte
  boundry). Saving RBP on the stack makes stack aligned again.
  Every call instruction besides implicitly saving RIP also saves __call_cookie
  which is used to validate ret instructions. Thus stack is aligned at any
  time/single VM instruction (each call takes 16 bytes on stack).
  Calling external procedures (printf, scanf) requires shadow space (32 bytes)
  on the stack with aligned requirement still holding. Alignment is not an issue
  here thanks to our VM calls convention.
 */

/*
  First four instruction for every program.
  Saves frame on the stack and loads address of first VM register into r15 and
  optionally address of first byte of data memory into r14 (non volatile
  registers)
 */
class prolog_machine_instr : public machine_instr
{
public:
    explicit prolog_machine_instr(bool mem_used) : mem_used_{mem_used} {}

    virtual dword size() const override
    {
        return 1 + 3 + 3 + sizeof(dword) +
               (mem_used_ ? (3 + sizeof(dword)) : 0);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // push rbp
        writer << 0x55_b;
        // mov rbp, rsp
        writer << 0x48_b << 0x89_b << 0xE5_b;

        // lea r15, [reg]
        writer << 0x4C_b << 0x8D_b << 0x3D_b
               << rip_relative{resolver.data.symbol("__registers")};

        if (mem_used_)
            // lea r14, [mem]
            writer << 0x4C_b << 0x8D_b << 0x35_b
                   << rip_relative{resolver.data.symbol("__memory")};
    }

private:
    const bool mem_used_;
};

/*
  Self-explanatory
 */
class nop_machine_instr : public machine_instr
{
public:
    virtual dword size() const override { return 1; }
    virtual void generate(machine_code_writer& writer, const resolver&) override
    {
        // nop
        writer << 0x90_b;
    }
};

/*
  Calls scanf from msvcrt.dll with given VM register as second argument
 */
class in_machine_instr : public machine_instr
{
public:
    in_machine_instr(byte reg) : reg_{reg} { validate_register(reg); }

    virtual dword size() const override
    {
        return 4 + 2 + reg_displacement_size(reg_) + 3 + sizeof(dword) + 2 +
               sizeof(dword) + 4;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // sub rsp, 32
        writer << 0x48_b << 0x83_b << 0xEC_b << 0x20_b;
        // lea rdx, qword [r15+%r*8]
        writer << 0x49_b << 0x8D_b << displacement<0x17_b>{reg_};
        // lea rcx, [__input_fmt]
        writer << 0x48_b << 0x8D_b << 0x0D_b
               << rip_relative{resolver.data.symbol("__input_fmt")};
        // call qword [__thunk_scanf]
        writer << 0xFF_b << 0x15_b
               << rip_relative{resolver.import.symbol("scanf")};
        // add rsp, 32
        writer << 0x48_b << 0x83_b << 0xC4_b << 0x20_b;
    }

private:
    const byte reg_;
};

/*
  Calls printf from msvcrt.dll with given VM register as second argument
 */
class out_machine_instr : public machine_instr
{
public:
    out_machine_instr(byte reg) : reg_{reg} { validate_register(reg); }

    virtual dword size() const override
    {
        return 4 + 2 + reg_displacement_size(reg_) + 3 + sizeof(dword) + 2 +
               sizeof(dword) + 4;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // sub rsp, 32
        writer << 0x48_b << 0x83_b << 0xEC_b << 0x20_b;
        // mov rdx, qword [r15+%r*8]
        writer << 0x49_b << 0x8B_b << displacement<0x17_b>{reg_};
        // lea rcx, [__output_fmt]
        writer << 0x48_b << 0x8D_b << 0x0D_b
               << rip_relative{resolver.data.symbol("__output_fmt")};
        // call qword [__thunk_printf]
        writer << 0xFF_b << 0x15_b
               << rip_relative{resolver.import.symbol("printf")};
        // add rsp, 32
        writer << 0x48_b << 0x83_b << 0xC4_b << 0x20_b;
    }

private:
    const byte reg_;
};

/*
  Stores VM register value to memory address pointed by another VM register
  Verifies if memory access is in proper bounds
 */
class store_machine_instr : public machine_instr
{
public:
    store_machine_instr(byte dst, byte src, dword mem_size)
        : dst_{dst}, src_{src}, mem_size_{mem_size}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(src_) + 3 + 2 + sizeof(dword) + 4 + 2 +
               sizeof(dword) + 2 + sizeof(dword) + 2 +
               reg_displacement_size(dst_) + 4;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // mov r8, qword [r15+%s*8]
        writer << 0x4D_b << 0x8B_b << displacement<0x07_b>{dst_};
        // test r8, r8
        writer << 0x4D_b << 0x85_b << 0xC0_b;
        // js $__out_of_bounds
        writer << 0x0F_b << 0x88_b
               << rip_relative{resolver.label.symbols("$__out_of_bounds")};
        // lea rax, [r8+8]
        writer << 0x49_b << 0x8D_b << 0x40_b << 0x08_b;
        // cmp rax, mem_size
        writer << 0x48_b << 0x3D_b << mem_size_;
        // ja $__out_of_bounds
        writer << 0x0F_b << 0x87_b
               << rip_relative{resolver.label.symbols("$__out_of_bounds")};
        // mov r9, qword [r15+0]
        writer << 0x4D_b << 0x8B_b << displacement<0x0F_b>{src_};
        // mov qword [r14+r8], r9
        writer << 0x4F_b << 0x89_b << 0x0C_b << 0x06_b;
    }

private:
    const byte dst_;
    const byte src_;
    const dword mem_size_;
};

/*
  Loads to VM register value from memory address pointed by another VM register.
  Verifies if memory access is in proper bounds
 */
class load_machine_instr : public machine_instr
{
public:
    load_machine_instr(byte dst, byte src, dword mem_size)
        : dst_{dst}, src_{src}, mem_size_{mem_size}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(src_) + 3 + 2 + sizeof(dword) + 4 + 2 +
               sizeof(dword) + 2 + sizeof(dword) + 4 + 2 +
               reg_displacement_size(dst_);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // mov r8, qword [r15+%s*8]
        writer << 0x4D_b << 0x8B_b << displacement<0x07_b>{src_};
        // test r8, r8
        writer << 0x4D_b << 0x85_b << 0xC0_b;
        // js $__out_of_bounds
        writer << 0x0F_b << 0x88_b
               << rip_relative{resolver.label.symbols("$__out_of_bounds")};
        // lea rax, [r8+8]
        writer << 0x49_b << 0x8D_b << 0x40_b << 0x08_b;
        // cmp rax, mem_size
        writer << 0x48_b << 0x3D_b << mem_size_;
        // ja $__out_of_bounds
        writer << 0x0F_b << 0x87_b
               << rip_relative{resolver.label.symbols("$__out_of_bounds")};
        // mov r9, [r14+r8]
        writer << 0x4F_b << 0x8B_b << 0x0C_b << 0x06_b;
        // mov qword [r15+%r*8], r9
        writer << 0x4D_b << 0x89_b << displacement<0x0F_b>{dst_};
    }

private:
    const byte dst_;
    const byte src_;
    const dword mem_size_;
};

/*
  Loads immediate value (byte) into given VM register
 */
class ldc_machine_instr : public machine_instr
{
public:
    ldc_machine_instr(byte dst, byte imm) : dst_{dst}, imm_{imm}
    {
        validate_register(dst);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(dst_) + sizeof(dword);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver&) override
    {
        // mov [r15+%r*8], imm32
        writer << 0x49_b << 0xC7_b << displacement<0x07_b>{dst_}
               << static_cast<dword>(imm_);
    }

private:
    const byte dst_;
    const byte imm_;
};

/*
  Copies value from one VM register to another
 */
class mov_machine_instr : public machine_instr
{
public:
    mov_machine_instr(byte dst, byte src) : dst_{dst}, src_{src}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(src_) + 2 +
               reg_displacement_size(dst_);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver&) override
    {
        // mov r8, [r15+%s*8]
        writer << 0x4D_b << 0x8B_b << displacement<0x07_b>{src_};
        // mov qword [r15+%r*8], r8
        writer << 0x4D_b << 0x89_b << displacement<0x07_b>{dst_};
    }

private:
    const byte dst_;
    const byte src_;
};

/*
  Adds value of one VM register to another storing the result in first operand
 */
class add_machine_instr : public machine_instr
{
public:
    add_machine_instr(byte dst, byte src) : dst_{dst}, src_{src}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(dst_) + 2 +
               reg_displacement_size(src_) + 3;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver&) override
    {
        // lea r8, [r15+%r*8]
        writer << 0x4D_b << 0x8D_b << displacement<0x07_b>{dst_};
        // mov r9, [r15+%s*8]
        writer << 0x4D_b << 0x8B_b << displacement<0x0F_b>{src_};
        // add qword [r8], r9
        writer << 0x4D_b << 0x01_b << 0x08_b;
    }

private:
    const byte dst_;
    const byte src_;
};

/*
  Subtracts value of VM register from another storing the result in first
  operand
 */
class sub_machine_instr : public machine_instr
{
public:
    sub_machine_instr(byte dst, byte src) : dst_{dst}, src_{src}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(dst_) + 2 +
               reg_displacement_size(src_) + 3;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver&) override
    {
        // lea r8, [r15+%r*8]
        writer << 0x4D_b << 0x8D_b << displacement<0x07_b>{dst_};
        // mov r9, [r15+%s*8]
        writer << 0x4D_b << 0x8B_b << displacement<0x0F_b>{src_};
        // sub qword [r8], r9
        writer << 0x4D_b << 0x29_b << 0x08_b;
    }

private:
    const byte dst_;
    const byte src_;
};

/*
  Multiplies value of VM register with another storing the result in first
  operand
 */
class mul_machine_instr : public machine_instr
{
public:
    mul_machine_instr(byte dst, byte src) : dst_{dst}, src_{src}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(dst_) + 3 + 3 +
               reg_displacement_size(src_) + 3;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver&) override
    {
        // lea r8, [r15+%r*8]
        writer << 0x4D_b << 0x8D_b << displacement<0x07_b>{dst_};
        // mov r9, qword [r8]
        writer << 0x4D_b << 0x8B_b << 0x08_b;
        // imul r9, qword [r15+%s*8]
        writer << 0x4D_b << 0x0F_b << 0xAF_b << displacement<0x0F_b>{src_};
        // mov qword [r8], r9
        writer << 0x4D_b << 0x89_b << 0x08_b;
    }

private:
    const byte dst_;
    const byte src_;
};

/*
  Calculates integer quotient of one VM register with another
 */
class div_machine_instr : public machine_instr
{
public:
    div_machine_instr(byte dst, byte src) : dst_{dst}, src_{src}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(src_) + 1 + 2 + sizeof(dword) + 2 +
               reg_displacement_size(dst_) + 3 + 2 + 2 +
               reg_displacement_size(src_) + 3;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // cmp qword [r15+%s*8], 0
        writer << 0x49_b << 0x83_b << displacement<0x3F_b>{src_} << 0x00_b;
        // je $__division_by_zero
        writer << 0x0F_b << 0x84_b
               << rip_relative{resolver.label.symbols("$__division_by_zero")};
        // lea r8, [r15+%r*8]
        writer << 0x4D_b << 0x8D_b << displacement<0x07_b>{dst_};
        // mov rax, qword [r8]
        writer << 0x49_b << 0x8B_b << 0x00_b;
        // cqo
        writer << 0x48_b << 0x99_b;
        // idiv rax, qword [r15+%s*8]
        writer << 0x49_b << 0xF7_b << displacement<0x3F_b>{src_};
        // mov qword [r8], rax
        writer << 0x49_b << 0x89_b << 0x00_b;
    }

private:
    const byte dst_;
    const byte src_;
};

/*
  Calculates the remainder of division of one VM register by another
 */
class mod_machine_instr : public machine_instr
{
public:
    mod_machine_instr(byte dst, byte src) : dst_{dst}, src_{src}
    {
        validate_register(dst);
        validate_register(src);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(src_) + 1 + 2 + sizeof(dword) + 2 +
               reg_displacement_size(dst_) + 3 + 2 + 2 +
               reg_displacement_size(src_) + 3;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // cmp qword [r15+%s*8], 0
        writer << 0x49_b << 0x83_b << displacement<0x3F_b>{src_} << 0x00_b;
        // je $__division_by_zero
        writer << 0x0F_b << 0x84_b
               << rip_relative{resolver.label.symbols("$__division_by_zero")};
        // lea r8, [r15+%r*8]
        writer << 0x4D_b << 0x8D_b << displacement<0x07_b>{dst_};
        // mov rax, qword [r8]
        writer << 0x49_b << 0x8B_b << 0x00_b;
        // cqo
        writer << 0x48_b << 0x99_b;
        // idiv rax, qword [r15+%s*8]
        writer << 0x49_b << 0xF7_b << displacement<0x3F_b>{src_};
        // mov qword [r8], rdx
        writer << 0x49_b << 0x89_b << 0x10_b;
    }

private:
    const byte dst_;
    const byte src_;
};

/*
  Performs long jump if give VM register is equal to 0
 */
class jz_machine_instr : public machine_instr
{
public:
    jz_machine_instr(int idx, byte reg, byte n) : idx_{idx}, reg_{reg}, n_{n}
    {
        validate_register(reg);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(reg_) + 1 + 2 + sizeof(dword);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // cmp qword [r15+%r*8], 0
        writer << 0x49_b << 0x83_b << displacement<0x3F_b>{reg_} << 0x00_b;
        // je $n
        writer << 0x0F_b << 0x84_b
               << rip_relative{resolver.label.symbols(idx_ + 1 + n_)};
    }

private:
    const int idx_;
    const byte reg_;
    const byte n_;
};

/*
  Performs long jump if given VM register is less than 0
 */
class jl_machine_instr : public machine_instr
{
public:
    jl_machine_instr(int idx, byte reg, byte n) : idx_{idx}, reg_{reg}, n_{n}
    {
        validate_register(reg);
    }

    virtual dword size() const override
    {
        return 2 + reg_displacement_size(reg_) + 1 + 2 + sizeof(dword);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // cmp qword [r15+%r*8], 0
        writer << 0x49_b << 0x83_b << displacement<0x3F_b>{reg_} << 0x00_b;
        // jl $n
        writer << 0x0F_b << 0x8c_b
               << rip_relative{resolver.label.symbols(idx_ + 1 + n_)};
    }

private:
    const int idx_;
    const byte reg_;
    const byte n_;
};

/*
  Performs long jump (relative to next VM instruction)
 */
class jump_machine_instr : public machine_instr
{
public:
    jump_machine_instr(int idx, int16_t n) : idx_{idx}, n_{n} {}

    virtual dword size() const override { return 1 + sizeof(dword); }
    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // jump $n
        writer << 0xE9_b << rip_relative{resolver.label.symbols(idx_ + 1 + n_)};
    }

private:
    const int idx_;
    const int16_t n_;
};

/*
  Performs long call (relative to next VM instruction)
  In addition to (implicit) RIP it also stores __call_cookie at the stack for
  the time of call. It's verified on each ret
 */
class call_machine_instr : public machine_instr
{
public:
    call_machine_instr(int idx, int16_t n) : idx_{idx}, n_{n} {}

    virtual dword size() const override
    {
        return 3 + sizeof(dword) + 1 + 1 + sizeof(dword) + 1;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // mov rax, qword [__call_cookie]
        writer << 0x48_b << 0x8B_b << 0x05_b
               << rip_relative{resolver.data.symbol("__call_cookie")};
        // push rax
        writer << 0x50_b;
        // call $n
        writer << 0xE8_b << rip_relative{resolver.label.symbols(idx_ + 1 + n_)};
        // pop rax
        writer << 0x58_b;
    }

private:
    const int idx_;
    const int16_t n_;
};

/*
  Returns from previous call. Checks if we don't underflow
 */
class ret_machine_instr : public machine_instr
{
public:
    virtual dword size() const override
    {
        return 5 + 3 + sizeof(dword) + 2 + sizeof(dword) + 1;
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // mov rax, [rsp+8]
        writer << 0x48_b << 0x8B_b << 0x44_b << 0x24_b << 0x08_b;
        // cmp rax, qword [__call_cookie]
        writer << 0x48_b << 0x3B_b << 0x05_b
               << rip_relative{resolver.data.symbol("__call_cookie")};
        // jnz _Underflow
        writer << 0x0F_b << 0x85_b
               << rip_relative{resolver.label.symbols("$__ret_underflow")};
        // ret
        writer << 0xC3_b;
    }
};

/*
  Performs long jump to $__epilog label
 */
class hlt_machine_instr : public machine_instr
{
public:
    virtual dword size() const override { return 1 + sizeof(dword); }
    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // jmp $__epilog
        writer << 0xE9_b << rip_relative{resolver.label.symbols("$__epilog")};
    }
};

/*
  Restores old RPB, cleans up the stack and returns to process'es caller
 */
class epilog_machine_instr : public machine_instr
{
public:
    virtual dword size() const override { return 3 + 1 + 2 + 1; }
    virtual void generate(machine_code_writer& writer,
                          const resolver&) override
    {
        // mov rsp, rbp
        writer << 0x48_b << 0x89_b << 0xEC_b;
        // pop rbp
        writer << 0x5D_b;
        // xor eax, eax
        writer << 0x31_b << 0xC0_b;
        // ret
        writer << 0xC3_b;

        /* Different version (doesn't care about cleaning the stack)
        // xor rcx, rcx
        writer << 0x48_b << 0x31_b << 0xC9_b;
        // call qword [__thunk_ExitProcess]
        writer << 0xFF_b << 0x15_b
               << rip_relative{resolver.import.symbol("ExitProcess")};
        */
    }
};

/*
  Prints error message about OOB access and jumps to $__epilog effectively
  terminating program
 */
class out_of_bounds_machine_instr : public machine_instr
{
public:
    virtual dword size() const override
    {
        return 4 + 3 + sizeof(dword) + 2 + sizeof(dword) + 4 + 1 +
               sizeof(dword);
    }
    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // sub rsp, 32
        writer << 0x48_b << 0x83_b << 0xEC_b << 0x20_b;
        // lea rcx, [__out_of_bounds]
        writer << 0x48_b << 0x8D_b << 0x0D_b
               << rip_relative{resolver.data.symbol("__out_of_bounds")};
        // call qword [__thunk_printf]
        writer << 0xFF_b << 0x15_b
               << rip_relative{resolver.import.symbol("printf")};
        // add rsp, 32
        writer << 0x48_b << 0x83_b << 0xC4_b << 0x20_b;
        // jmp $__epilog
        writer << 0xE9_b << rip_relative{resolver.label.symbols("$__epilog")};
    }
};

/*
  Prints error message about division by zero and jumps to $__epilog effectively
  terminating program
 */
class division_by_zero_machine_instr : public machine_instr
{
public:
    virtual dword size() const override
    {
        return 4 + 3 + sizeof(dword) + 2 + sizeof(dword) + 4 + 1 +
               sizeof(dword);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // sub rsp, 32
        writer << 0x48_b << 0x83_b << 0xEC_b << 0x20_b;
        // lea rcx, [__division_by_zero]
        writer << 0x48_b << 0x8D_b << 0x0D_b
               << rip_relative{resolver.data.symbol("__division_by_zero")};
        // call qword [__thunk_printf]
        writer << 0xFF_b << 0x15_b
               << rip_relative{resolver.import.symbol("printf")};
        // add rsp, 32
        writer << 0x48_b << 0x83_b << 0xC4_b << 0x20_b;
        // jmp $__epilog
        writer << 0xE9_b << rip_relative{resolver.label.symbols("$__epilog")};
    }
};

/*
  Prints error message about stack underflow and jumps to $__epilog effectively
  terminating program
 */
class return_underflow_machine_instr : public machine_instr
{
public:
    virtual dword size() const override
    {
        return 4 + 3 + sizeof(dword) + 2 + sizeof(dword) + 4 + 1 +
               sizeof(dword);
    }

    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) override
    {
        // sub rsp, 32
        writer << 0x48_b << 0x83_b << 0xEC_b << 0x20_b;
        // lea rcx, [__ret_underflow]
        writer << 0x48_b << 0x8D_b << 0x0D_b
               << rip_relative{resolver.data.symbol("__ret_underflow")};
        // call qword [__thunk_printf]
        writer << 0xFF_b << 0x15_b
               << rip_relative{resolver.import.symbol("printf")};
        // add rsp, 32
        writer << 0x48_b << 0x83_b << 0xC4_b << 0x20_b;
        // jmp $__epilog
        writer << 0xE9_b << rip_relative{resolver.label.symbols("$__epilog")};
    }
};

codegen::codegen(const vector<bytecode_instr>& bytecode, dword mem_size,
                 const data_symbols& datas, const import_symbols& imports)
    : resolver_{labels_, datas, imports}, mem_size_{mem_size}
{
    // include runtime named instruction blocks
    instrs_.reserve(bytecode.size() + 4);
    labels_.reserve(bytecode.size() + 4);

    inject_custom_instr<prolog_machine_instr>("$__prolog", mem_size > 0);

    int idx = 0;

    for (const auto& bc_instr : bytecode)
    {
        auto instr = factory_machine_instr(idx, bc_instr);
        labels_.add(instr->size());
        instrs_.push_back(std::move(instr));
        ++idx;
    }

    inject_custom_instr<epilog_machine_instr>("$__epilog");
    inject_custom_instr<out_of_bounds_machine_instr>("$__out_of_bounds");
    inject_custom_instr<division_by_zero_machine_instr>("$__division_by_zero");
    inject_custom_instr<return_underflow_machine_instr>("$__ret_underflow");
}

vector<byte> codegen::build()
{
    labels_.set_rva(virtual_addr_);
    machine_code_writer writer{virtual_addr_};
    for (const auto& i : instrs_)
        i->generate(writer, resolver_);
    const auto code = writer.get();
    if (code.size() != code_size())
        throw std::runtime_error{"error during generating code"};
    return code;
}

dword codegen::code_size() const
{
    return std::accumulate(
        begin(instrs_), end(instrs_), (dword)0,
        [](dword acc, const auto& i) { return acc + i->size(); });
}

unique_ptr<machine_instr>
    codegen::factory_machine_instr(int idx, const bytecode_instr& bc_instr)
{
    // Here we assume bytecode is valid (i.e registers are correct)
    switch (bc_instr.op)
    {
    case opcode::nop:
        return std::make_unique<nop_machine_instr>();
    case opcode::in:
        return std::make_unique<in_machine_instr>(bc_instr.dst);
    case opcode::out:
        return std::make_unique<out_machine_instr>(bc_instr.dst);
    case opcode::store:
        return std::make_unique<store_machine_instr>(bc_instr.dst, bc_instr.src,
                                                     mem_size_);
    case opcode::load:
        return std::make_unique<load_machine_instr>(bc_instr.dst, bc_instr.src,
                                                    mem_size_);
    case opcode::ldc:
        return std::make_unique<ldc_machine_instr>(bc_instr.dst, bc_instr.src);
    case opcode::mov:
        return std::make_unique<mov_machine_instr>(bc_instr.dst, bc_instr.src);
    case opcode::add:
        return std::make_unique<add_machine_instr>(bc_instr.dst, bc_instr.src);
    case opcode::sub:
        return std::make_unique<sub_machine_instr>(bc_instr.dst, bc_instr.src);
    case opcode::mul:
        return std::make_unique<mul_machine_instr>(bc_instr.dst, bc_instr.src);
    case opcode::div:
        return std::make_unique<div_machine_instr>(bc_instr.dst, bc_instr.src);
    case opcode::mod:
        return std::make_unique<mod_machine_instr>(bc_instr.dst, bc_instr.src);
    case opcode::jz:
        return std::make_unique<jz_machine_instr>(idx, bc_instr.dst,
                                                  bc_instr.src);
    case opcode::jl:
        return std::make_unique<jl_machine_instr>(idx, bc_instr.dst,
                                                  bc_instr.src);
    case opcode::jump:
        return std::make_unique<jump_machine_instr>(idx, imm16(bc_instr));
    case opcode::call:
        return std::make_unique<call_machine_instr>(idx, imm16(bc_instr));
    case opcode::ret:
        return std::make_unique<ret_machine_instr>();
    case opcode::hlt:
        return std::make_unique<hlt_machine_instr>();
    default:
    {
        std::ostringstream strm;
        strm << "invalid opcode: 0x" << std::hex
             << static_cast<int>(bc_instr.op);
        throw std::runtime_error{strm.str()};
    }
    }
}
