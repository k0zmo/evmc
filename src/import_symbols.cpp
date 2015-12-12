#include "import_symbols.h"
#include <Windows.h>
#include <sstream>

import_symbols::import_dll&
    import_symbols::import_dll::import_procedure(string proc_name, word hint)
{
    const auto needle =
        std::find_if(begin(imports_), end(imports_),
                     [&](const auto& proc) { return proc.name == proc_name; });
    if (needle != end(imports_))
        throw std::runtime_error{"procedure with given name alread added"};
    imports_.emplace_back(std::move(proc_name), hint);
    return *this;
}

import_symbols::import_dll& import_symbols::add_dll(string name)
{
    const auto needle =
        std::find_if(begin(import_dlls_), end(import_dlls_),
                     [&](const auto& dll) { return dll.name_ == name; });
    if (needle != end(import_dlls_))
        throw std::runtime_error{"dll with given name alread added"};
    import_dlls_.push_back(import_dll{std::move(name)});
    return import_dlls_.back();
}

void import_symbols::prepare()
{
    // calculate offsets for import directory
    const size_t num_thunks = std::accumulate(
        begin(import_dlls_), end(import_dlls_), (size_t)0,
        [](size_t num_proc, const auto& dll) {
            return num_proc + (dll.num_imports() + 1); // include sentinel thunk
        });
    const size_t num_descs = (import_dlls_.size() + 1);

    const size_t original_thunks_dist =
        num_thunks * sizeof(qword) +
        num_descs * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    const size_t start_directory =
        original_thunks_dist + num_thunks * sizeof(qword);

    thunks_.clear();
    thunks_.reserve(num_thunks);
    descs_.clear();
    descs_.reserve(num_descs);

    size_t entry_addr = start_directory;
    size_t thunk_addr = 0;

    for (const auto& dll : import_dlls_)
    {
        descs_.push_back({});
        auto& d = descs_.back();

        d.Name = static_cast<dword>(entry_addr);
        d.FirstThunk = static_cast<dword>(thunk_addr);
        d.OriginalFirstThunk =
            d.FirstThunk + static_cast<dword>(original_thunks_dist);

        // BYTE[] DllName;
        entry_addr += dll.name_.length() + 2; // two \0\0
        for (const auto& proc : dll.imports_)
        {
            // WORD Hint
            // BYTE[] Name
            thunks_.emplace_back((qword)entry_addr);
            entry_addr += sizeof(word) + proc.name.length() + 1;
        }
        thunks_.push_back({}); // sentinel
        thunk_addr += (dll.imports_.size() + 1) * sizeof(qword);
    }
    descs_.push_back({}); // sentinel
}

vector<byte> import_symbols::build()
{
    // Make sure IAT will fit in given address space)
    incr_check_overflow(virtual_addr_, total_size());

    // assume little endian
    std::ostringstream strm;

    // Thunks
    for (auto thunk : thunks_)
        write_bytes(strm, thunk == 0 ? 0 : thunk + virtual_addr_);

    for (auto desc : descs_)
    {
        if (desc.OriginalFirstThunk != 0)
        {
            desc.OriginalFirstThunk += virtual_addr_;
            desc.FirstThunk += virtual_addr_;
            desc.Name += virtual_addr_;
        }
        write_bytes(strm, desc);
    }

    // Original thunks
    for (auto thunk : thunks_)
        write_bytes(strm, thunk == 0 ? 0 : thunk + virtual_addr_);

    // Directory
    for (const auto& dll : import_dlls_)
    {
        strm << dll.name_;
        strm << 0_b << 0_b;
        for (const auto& proc : dll.imports_)
        {
            write_bytes(strm, proc.hint);
            strm << proc.name << 0_b;
        }
    }

    auto str = strm.str();
    return {begin(str), end(str)};
}

dword import_symbols::total_size() const
{
    size_t directory_size = 0;

    for (const auto& dll : import_dlls_)
    {
        directory_size += dll.name_.length() + 2;
        for (const auto& proc : dll.imports_)
        {
            directory_size += sizeof(word);
            directory_size += proc.name.length() + 1;
        }
    }

    return 2 * iat_size() + import_dir_size() +
           static_cast<dword>(directory_size);
}

dword import_symbols::symbol(const char* name) const
{
    for (size_t i = 0; i < import_dlls_.size(); ++i)
    {
        int slot = import_dlls_[i].import_slot(name);
        if (slot != -1)
        {
            size_t imp_sofar =
                std::accumulate(begin(import_dlls_), begin(import_dlls_) + i,
                                (size_t)0, [](size_t acc, const auto& dll) {
                                    return acc + 1 + dll.num_imports();
                                });
            return static_cast<dword>(virtual_addr_ +
                                      (imp_sofar + slot) * sizeof(qword));
        }
    }

    throw std::runtime_error{"extern procedure with given name not found"};
}
