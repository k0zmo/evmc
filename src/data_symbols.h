#pragma once

#include "prerequisites.h"
#include <sstream>

class data_symbols
{
public:
    void add(string symbol_name, const char* data);
    void add(string symbol_name, std::istream& is, dword num_bytes);

    template <typename T,
              class = std::enable_if_t<std::is_standard_layout<T>::value>>
    void add(string symbol_name, const T& value)
    {
        check_duplicates(symbol_name);
        write_bytes(strm_, value);
        symbols_.emplace_back(std::move(symbol_name), current_offset_);
        current_offset_ = incr_check_overflow(current_offset_, sizeof(T));
    }

    template <typename T,
              class = std::enable_if_t<std::is_standard_layout<T>::value>>
    void add_zeros(string symbol_name, size_t dup)
    {
        check_duplicates(symbol_name);
        cached_zeros_ = incr_check_overflow(cached_zeros_, dup * sizeof(T));
        symbols_.emplace_back(std::move(symbol_name), current_offset_);
        current_offset_ = incr_check_overflow(current_offset_, dup * sizeof(T));
    }

    dword raw_size();
    dword virtual_size();

    vector<byte> build();

    void set_rva(dword addr) { virtual_addr_ = addr; }
    dword symbol(const char* name) const;

private:
    void check_duplicates(const std::string& symbol_name);
    void check_cached_zeros();

private:
    vector<pair<string, dword>> symbols_;
    std::ostringstream strm_;
    dword current_offset_{0};
    dword virtual_addr_{0};
    dword cached_zeros_{0};
};
