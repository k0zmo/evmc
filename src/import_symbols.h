#pragma once

#include "prerequisites.h"
#include <Windows.h>

class import_symbols
{
public:
    class import_dll
    {
        friend class import_symbols;

    public:
        import_dll& import_procedure(string proc_name, word hint = 0);
        size_t num_imports() const { return imports_.size(); }
        int import_slot(const char* name) const
        {
            const auto needle = std::find_if(
                begin(imports_), end(imports_),
                [name](const auto& imp) { return imp.name == name; });
            if (needle != end(imports_))
                return static_cast<int>(needle - begin(imports_));
            return -1;
        }

    private:
        explicit import_dll(string name) : name_{std::move(name)} {}

    private:
        struct import_proc final
        {
            import_proc(string name, word hint)
                : name{std::move(name)}, hint{hint}
            {
            }

            string name;
            word hint;
        };

        string name_;
        vector<import_proc> imports_;
    };

    import_dll& add_dll(string name);
    void prepare();
    vector<byte> build();

    void set_rva(dword virtual_addr) { virtual_addr_ = virtual_addr; }

    dword iat_size() const
    {
        return static_cast<dword>(thunks_.size() * sizeof(qword));
    }
    dword import_dir_size() const
    {
        return static_cast<dword>(descs_.size() *
                                  sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    dword total_size() const;
    dword symbol(const char* name) const;

private:
    vector<import_dll> import_dlls_;
    vector<qword> thunks_;
    vector<IMAGE_IMPORT_DESCRIPTOR> descs_;
    dword virtual_addr_{0};
};
