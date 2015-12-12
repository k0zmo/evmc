#include "prerequisites.h"

#include <iomanip>

namespace {
struct evm_register
{
    evm_register(byte index) : index{index} {}
    byte index;
};

std::ostream& operator<<(std::ostream& os, evm_register r)
{
    return os << "r" << +r.index;
}
}

std::ostream& operator<<(std::ostream& os, const bytecode_instr& i)
{
    switch (i.op)
    {
    case opcode::nop:
        os << "nop";
        break;
    case opcode::in:
        os << "in " << evm_register{i.dst};
        break;
    case opcode::out:
        os << "out " << evm_register{i.dst};
        break;
    case opcode::store:
        os << "store " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::load:
        os << "load " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::ldc:
        os << "ldc " << evm_register{i.dst} << ", $" << +i.src;
        break;
    case opcode::mov:
        os << "mov " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::add:
        os << "add " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::sub:
        os << "sub " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::mul:
        os << "mul " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::div:
        os << "div " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::mod:
        os << "mod " << evm_register{i.dst} << ", " << evm_register{i.src};
        break;
    case opcode::jz:
        os << "jz " << evm_register{i.dst} << ", $" << +i.src;
        break;
    case opcode::jl:
        os << "jl " << evm_register{i.dst} << ", $" << +i.src;
        break;
    case opcode::jump:
        os << "jump "
           << "$" << imm16(i);
        break;
    case opcode::call:
        os << "call "
           << "$" << imm16(i);
        break;
    case opcode::ret:
        os << "ret";
        break;
    case opcode::hlt:
        os << "hlt";
        break;
    }
    return os;
}

std::ostream& operator<<(std::ostream& os, const vector<bytecode_instr>& is)
{
    os << ".code\n";
    for (size_t ip = 0; ip < is.size(); ++ip)
    {
        std::ios state{nullptr};
        state.copyfmt(os);
        os << "  " << std::setfill('0') << std::setw(4) << ip;

        os.copyfmt(state);
        os << ": " << is[ip] << "\n";
    }

    return os;
}
