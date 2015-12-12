#pragma once

#include "prerequisites.h"

class bytecode_reader
{
public:
    explicit bytecode_reader(const char* filename);
    explicit bytecode_reader(vector<bytecode_instr> bytecode);

    const evm_header& header() const { return evm_header_; }
    const vector<bytecode_instr>& bytecode() const { return bytecode_; }
    std::istream& initial_data_stream() { return in_file_; }

private:
    void read_bytecode(size_t n);

    static size_t get_valid_file_size(const evm_header& header);
    static bool validate_header(const evm_header& header, qword file_size);
    static void debug_output(const bytecode_reader& bcr);

private:
    constexpr static const char* FILE_ID = "ESET-VM1";
    evm_header evm_header_ = {};
    vector<bytecode_instr> bytecode_;
    std::ifstream in_file_;
};
