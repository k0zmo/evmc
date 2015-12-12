#include "bytecode_reader.h"

#include <cstring>
#include <iostream>

bytecode_reader::bytecode_reader(const char* filename)
{
    in_file_.open(filename, std::ios::binary | std::ios::in);
    const auto errMask = std::ifstream::failbit | std::ifstream::eofbit;
    in_file_.exceptions(errMask);

    // Get file size
    std::streampos fsize = in_file_.tellg();
    in_file_.seekg(0, std::ios::end);
    fsize = in_file_.tellg() - fsize;
    in_file_.seekg(0, std::ios::beg);

    // Read header
    read_bytes(in_file_, evm_header_);
    // Validate file against its header
    if (!validate_header(evm_header_, fsize))
        throw std::runtime_error{"invalid EVM header"};
    in_file_.exceptions(~(errMask));

    read_bytecode(evm_header_.code_size);
#if defined(_DEBUG)
    debug_output(*this);
#endif
}

bytecode_reader::bytecode_reader(vector<bytecode_instr> stream)
    : bytecode_{std::move(stream)}
{
    evm_header_ = {};
    evm_header_.code_size = sizeof(bytecode_);
#if defined(_DEBUG)
    debug_output(*this);
#endif
}

void bytecode_reader::read_bytecode(size_t n)
{
    bytecode_.clear();
    bytecode_.reserve(n);
    while (bytecode_.size() < n)
    {
        bytecode_instr instr;
        read_bytes(in_file_, instr);
        if (in_file_.gcount() != sizeof(instr))
            break;
        bytecode_.push_back(instr);
    }
}

size_t bytecode_reader::get_valid_file_size(const evm_header& header)
{
    return header.code_size * sizeof(bytecode_instr) +
           header.initial_data_size + sizeof(evm_header);
}

bool bytecode_reader::validate_header(const evm_header& header, qword file_size)
{
    return get_valid_file_size(header) == file_size &&
           !memcmp(header.magic, FILE_ID, strlen(FILE_ID)) &&
           header.data_size >= header.initial_data_size;
}

void bytecode_reader::debug_output(const bytecode_reader& bcr)
{
    std::cout << "data size: " << bcr.header().data_size << "\n";
    std::cout << "initial data size: " << bcr.header().initial_data_size
              << "\n\n";
    std::cout << bcr.bytecode() << std::endl;
}
