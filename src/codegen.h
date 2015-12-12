#pragma once

#include "prerequisites.h"
#include <sstream>

class import_symbols;
class data_symbols;

class label_symbols
{
public:
    void reserve(size_t n) { labels_.reserve(n); }
    void add(std::string name, dword size);
    void add(dword size);
    dword symbols(const char* name) const;
    dword symbols(size_t idx) const;
    void set_rva(dword rva);

private:
    void check_duplicates(const std::string& label_name);

private:
    vector<pair<string, dword>> labels_;
    vector<dword> n_labels_;
    dword current_offset_{0};
};

struct resolver
{
    resolver(const label_symbols& label, const data_symbols& data,
             const import_symbols& import)
        : label{label}, data{data}, import{import}
    {
    }

    const label_symbols& label;
    const data_symbols& data;
    const import_symbols& import;
};

struct rip_relative;

class machine_code_writer
{
public:
    machine_code_writer(dword code_rva) : code_rva_{code_rva} {}

    machine_code_writer& operator<<(byte b);
    machine_code_writer& operator<<(dword addr);
    machine_code_writer& operator<<(rip_relative abs);

    vector<byte> get() const;

private:
    std::ostringstream strm_;
    dword code_rva_;
    std::streampos offset_{0};
};

class machine_instr
{
public:
    virtual ~machine_instr() = default;
    virtual dword size() const = 0;
    virtual void generate(machine_code_writer& writer,
                          const resolver& resolver) = 0;
};

class codegen
{
public:
    codegen(const vector<bytecode_instr>& bytecode, dword mem_size,
            const data_symbols& datas, const import_symbols& imports);

    void set_rva(dword virtual_addr) { virtual_addr_ = virtual_addr; }
    vector<byte> build();
    dword code_size() const;

private:
    template <typename MachineInstr, typename... Args>
    void inject_custom_instr(string label_name, Args&&... args)
    {
        instrs_.push_back(
            std::make_unique<MachineInstr>(std::forward<Args>(args)...));
        labels_.add(std::move(label_name), instrs_.back()->size());
    }

    unique_ptr<machine_instr>
        factory_machine_instr(int idx, const bytecode_instr& bc_instr);

private:
    label_symbols labels_;
    vector<unique_ptr<machine_instr>> instrs_;
    resolver resolver_;
    const dword mem_size_;
    dword virtual_addr_{0};
};
