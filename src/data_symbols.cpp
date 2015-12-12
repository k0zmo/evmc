#include "data_symbols.h"
#include <cstring>

void data_symbols::add(string symbol_name, const char* data)
{
    check_duplicates(symbol_name);
    check_cached_zeros();
    strm_ << data;
    strm_ << 0_b;
    symbols_.emplace_back(std::move(symbol_name), current_offset_);
    current_offset_ = incr_check_overflow(current_offset_,
                                          static_cast<dword>(strlen(data) + 1));
}

void data_symbols::add(string symbol_name, std::istream& is, dword num_bytes)
{
    check_duplicates(symbol_name);
    check_cached_zeros();
    std::copy_n(std::istreambuf_iterator<char>(is), num_bytes,
                std::ostreambuf_iterator<char>(strm_));
    symbols_.emplace_back(std::move(symbol_name), current_offset_);
    current_offset_ = incr_check_overflow(current_offset_, num_bytes);
}

dword data_symbols::raw_size() { return static_cast<dword>(strm_.tellp()); }

dword data_symbols::virtual_size()
{
    return incr_check_overflow(raw_size(), cached_zeros_);
}

vector<byte> data_symbols::build()
{
    auto str = strm_.str();
    return {begin(str), end(str)};
}

dword data_symbols::symbol(const char* name) const
{
    const auto needle =
        std::find_if(begin(symbols_), end(symbols_),
                     [&](const auto& sym) { return sym.first == name; });
    if (needle == end(symbols_))
        throw std::runtime_error{"symbol with given does not exist"};
    return incr_check_overflow(needle->second, virtual_addr_);
}

void data_symbols::check_duplicates(const std::string& symbol_name)
{
    const auto needle =
        std::find_if(begin(symbols_), end(symbols_),
                     [&](const auto& sym) { return sym.first == symbol_name; });
    if (needle != end(symbols_))
        throw std::runtime_error{"symbol with given name alread added"};
}

void data_symbols::check_cached_zeros()
{
    for (size_t i = 0; i < cached_zeros_; ++i)
        strm_ << (byte)0;
    cached_zeros_ = 0;
}
