#pragma once

#include "prerequisites.h"
#include <Windows.h>

struct section_size final
{
    section_size(dword raw_section_size)
        : $virtual{raw_section_size}, raw{raw_section_size}
    {
    }

    section_size(dword virtual_section_size, dword raw_section_size)
        : $virtual{virtual_section_size}, raw{raw_section_size}
    {
    }

    dword $virtual{0};
    dword raw{0};
};

using section_headers = vector<IMAGE_SECTION_HEADER>;
class section_headers_builder
{
public:
    section_headers_builder() = default;

    section_headers_builder& add(const char* name, section_size size,
                                 dword flags);
    section_headers build();

private:
    struct section_header_desc
    {
        section_header_desc() = default;
        section_header_desc(const char* name, section_size size, dword flags);

        byte name[8] = {};
        section_size size;
        dword flags = {};
    };

    vector<section_header_desc> descs_;
};

class codegen;
class data_symbols;
class import_symbols;

class pe_writer
{
public:
    pe_writer(codegen& codegen, data_symbols& datas, import_symbols& imports)
        : code_gen_{&codegen}, datas_{&datas}, imports_{&imports}
    {
    }

    void write(const char* filename);

private:
    void write_dos_header(std::ostream& file) const;
    void write_nt_headers(std::ostream& file,
                          const section_headers& section_headers) const;
    void write_section(std::ostream& strm, const vector<byte>& bytes) const;

private:
    // observering pointers
    codegen* code_gen_;
    data_symbols* datas_;
    import_symbols* imports_;
};
