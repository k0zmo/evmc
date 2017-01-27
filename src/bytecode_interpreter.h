#pragma once

#include "prerequisites.h"
#include <stack>

class bytecode_stream
{
public:
    explicit bytecode_stream(const vector<bytecode_instr>& stream)
        : stream_{std::move(stream)}
    {
    }

    const bytecode_instr& fetch(size_t ip) const;
    bool stream_ends(size_t ip) const;

private:
    vector<bytecode_instr> stream_;
};

class bytecode_interpreter
{
public:
    bytecode_interpreter(std::istream& file, const evm_header& header);
    void run(const bytecode_stream& stream);

private:
    int64_t& reg(byte i);
    char* mem(int64_t addr);

private:
    int64_t regs_[NUM_REGISTERS] = {};
    size_t ip_ = {};
    std::stack<size_t> stack_;
    std::unique_ptr<char[]> data_;
    uint64_t mem_size_ = {};
};
