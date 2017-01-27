#include "bytecode_interpreter.h"
#include <cstring>

const bytecode_instr& bytecode_stream::fetch(size_t ip) const
{
    if (stream_ends(ip))
        throw std::runtime_error{"Error: Jump address out of bounds"};
    return stream_[ip];
}

bool bytecode_stream::stream_ends(size_t ip) const
{
    return ip >= stream_.size();
}

bytecode_interpreter::bytecode_interpreter(std::istream& file,
                                           const evm_header& evm_header)
{
    if (evm_header.data_size == 0)
        return;

    data_ = std::make_unique<char[]>(evm_header.data_size);
    mem_size_ = evm_header.data_size;

    if (evm_header.initial_data_size > 0)
    {
        file.read(data_.get() + 0, evm_header.initial_data_size);
        if (file.gcount() != evm_header.initial_data_size)
            throw std::runtime_error{"Error: Corrupted initial data"};
    }

    std::memset(data_.get() + evm_header.initial_data_size, 0,
                (evm_header.data_size - evm_header.initial_data_size) *
                    sizeof(byte));
}

void bytecode_interpreter::run(const bytecode_stream& stream)
{
    while (!stream.stream_ends(ip_))
    {
        const auto& instr = stream.fetch(ip_++);

        switch (instr.op)
        {
        // no operation
        case opcode::nop:
            break;
        // read hexadecimal value from standard input, and store in registry reg
        case opcode::in:
            scanf("%llX", &reg(instr.dst));
            break;
        // write hexadecimal value in registry reg to standard output
        case opcode::out:
            printf("%016llX\n", reg(instr.dst));
            break;
        // store value of reg2 in memory cell pointed by reg1
        case opcode::store:
            memcpy(mem(reg(instr.dst)), &reg(instr.src), sizeof(int64_t));
            break;
        // load value from memory cell pointed by reg2 into register_t reg1
        case opcode::load:
            memcpy(&reg(instr.dst), mem(reg(instr.src)), sizeof(int64_t));
            break;
        // load 8-bit immediate value to reg
        case opcode::ldc:
            reg(instr.dst) = instr.src;
            break;
        // copy value from register2 to register1
        case opcode::mov:
            reg(instr.dst) = reg(instr.src);
            break;
        // add value of reg2 to reg1, and save result in reg1
        case opcode::add:
            reg(instr.dst) += reg(instr.src);
            break;
        // subtract value of reg2 from reg1, and save result in reg1
        case opcode::sub:
            reg(instr.dst) -= reg(instr.src);
            break;
        // multiplies value of reg1 by value of reg2 and save result in reg1
        case opcode::mul:
            reg(instr.dst) *= reg(instr.src);
            break;
        // divides value of reg1 by value of reg2 and save result in reg1
        case opcode::div:
            if (reg(instr.src) == 0)
                throw std::runtime_error{"Error: Division by zero"};
            reg(instr.dst) /= reg(instr.src);
            break;
        // calculates reminder of division of reg1 by reg2 and save result in
        // reg1
        case opcode::mod:
            if (reg(instr.src) == 0)
                throw std::runtime_error{"Error: Division by zero"};
            reg(instr.dst) %= reg(instr.src);
            break;
        // if value of reg is zero, does relative jump.
        case opcode::jz:
            if (reg(instr.dst) == 0)
                ip_ = ip_ + static_cast<int8_t>(instr.src);
            break;
        // if value of reg is less then zero, does relative jump.
        case opcode::jl:
            if (reg(instr.dst) < 0)
                ip_ = ip_ + static_cast<int8_t>(instr.src);
            break;
        // unconditional relative jump by imm16.
        case opcode::jump:
            ip_ = ip_ + imm16(instr); // Will wrap if it goes to negative
            break;
        // stores next instruction pointer on internal stack and jumps by imm16.
        case opcode::call:
            stack_.push(ip_);
            ip_ = ip_ + imm16(instr);
            break;
        // reads absolute instruction pointer from stack and jumps to it(returns
        // to next instruction after corresponding CALL)
        case opcode::ret:
            if (stack_.empty())
                throw std::runtime_error{"Error: Call stack underflow"};
            ip_ = stack_.top();
            stack_.pop();
            break;
        // ends program, terminates execution
        case opcode::hlt:
            return;
        default:
            throw std::runtime_error("Error: Unknown instruction");
        }

        if (stream.stream_ends(ip_))
            throw std::runtime_error{"Error: Jump address out of bounds"};
    }
}

int64_t& bytecode_interpreter::reg(byte i)
{
    if (i >= NUM_REGISTERS)
        throw std::runtime_error{
            "Error: Instruction register_t index out of bounds"};
    return regs_[i];
}

char* bytecode_interpreter::mem(int64_t addr)
{
    if (addr < 0 || static_cast<uint64_t>(addr) + 8 > mem_size_)
        throw std::runtime_error{"Error: Runtime memory offset out of bounds"};
    return &data_[static_cast<size_t>(addr)];
}
