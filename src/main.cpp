#include "bytecode_interpreter.h"
#include "bytecode_reader.h"
#include "codegen.h"
#include "data_symbols.h"
#include "import_symbols.h"
#include "pe_writer.h"

#include <cstring>
#include <iostream>
#include <tuple>

data_symbols construct_data(bytecode_reader& bytecode_reader)
{
    data_symbols datas;
    // add "runtime" data symbols
    datas.add("__input_fmt", "%llx");
    datas.add("__output_fmt", "%016llX\n");
    datas.add("__out_of_bounds",
              "Error: Runtime memory offset out of bounds\n");
    datas.add("__division_by_zero", "Error: Division by zero\n");
    datas.add("__ret_underflow", "Error: Call stack underflow\n");
    datas.add("__call_cookie", 0x11223344AABBCCDDULL);
    datas.add_zeros<qword>("__registers", NUM_REGISTERS);

    const auto& evm_header = bytecode_reader.header();

    // add initialized data symbols (from the rest of input file stream)
    if (evm_header.initial_data_size)
    {
        datas.add("__memory", bytecode_reader.initial_data_stream(),
                  evm_header.initial_data_size);
        const auto bss_size =
            evm_header.data_size - evm_header.initial_data_size;
        if (bss_size)
            datas.add_zeros<byte>("__memory0", bss_size);
    }
    else if (evm_header.data_size)
    {
        // only zero'ed data
        datas.add_zeros<byte>("__memory", evm_header.data_size);
    }

    return datas;
}

import_symbols construct_iat()
{
    import_symbols imports;
    imports.add_dll("KERNEL32.dll")
        .import_procedure("ExitProcess", 0x120);
    imports.add_dll("msvcrt.dll")
        .import_procedure("printf", 0x48b)
        .import_procedure("scanf", 0x49b);
    imports.prepare();

    return imports;
}

int main(int argc, char* argv[]) try
{
    if (argc < 2)
    {
        std::cerr << "Usage: evmc.exe [-i] <filename>\n";
        return 0;
    }

    const auto opt = [&] {
        if (argc == 3 && !strcmp(argv[1], "-i"))
            return std::make_tuple(argv[2], true);
        return std::make_tuple(argv[1], false);
    }();

    bytecode_reader bytecode_reader{std::get<0>(opt)};

    if (!std::get<1>(opt))
    {
        data_symbols datas{construct_data(bytecode_reader)};
        import_symbols imports{construct_iat()};
        codegen codegen{bytecode_reader.bytecode(),
                        bytecode_reader.header().data_size, datas, imports};

        using namespace std::literals;
        const auto out_file = std::string{std::get<0>(opt)} + ".exe"s;
        pe_writer writer{codegen, datas, imports};
        writer.write(out_file.c_str());
    }
    else
    {
        bytecode_interpreter interpreter{bytecode_reader.initial_data_stream(),
                                         bytecode_reader.header()};
        interpreter.run(bytecode_stream{bytecode_reader.bytecode()});
    }
}
catch (std::exception& ex)
{
    std::cerr << ex.what() << std::endl;
}
