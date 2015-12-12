#include "codegen.h"
#include "data_symbols.h"
#include "import_symbols.h"
#include "pe_writer.h"

#include <cstring>

namespace {
const byte dos_stub[] = {0x0e,             // push cs
                         0x1f,             // pop ds
                         0xba, 0x0e, 0x00, // mov dx, 0x000E
                         0xb4, 0x09,       // mov ah, 9
                         0xcd, 0x21,       // int 0x21
                         0xb8, 0x01, 0x4c, // mov ax, 0x4C01
                         0xcd, 0x21,       // int 0x21
                         'T',  'h',  'i',  's', ' ', 'p', 'r', 'o', 'g', 'r',
                         'a',  'm',  ' ',  'c', 'a', 'n', 'n', 'o', 't', ' ',
                         'b',  'e',  ' ',  'r', 'u', 'n', ' ', 'i', 'n', ' ',
                         'D',  'O',  'S',  ' ', 'm', 'o', 'd', 'e', '.', '\r',
                         '\r', '\n', '$',  0,   0,   0,   0,   0,   0,   0};

const dword DOS_STUB_SIZE = sizeof(dos_stub);
const dword SECTION_ALIGNMENT = 0x00001000;
const dword FILE_ALIGNMENT = 0x00000200;
const dword OS_MAJOR = 6;
const dword OS_MINOR = 0;

enum { text, data, idata, kNumSections };
const dword SECTION_FLAGS[kNumSections] = {
    IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ};

dword all_headers_size(size_t num_section)
{
    const size_t SECTION_HEADERS_FILE_OFFSET =
        sizeof(IMAGE_DOS_HEADER) + DOS_STUB_SIZE + sizeof(IMAGE_NT_HEADERS64);

    return align(static_cast<dword>(SECTION_HEADERS_FILE_OFFSET +
                                    num_section * sizeof(IMAGE_SECTION_HEADER)),
                 FILE_ALIGNMENT);
}
}

section_headers_builder::section_header_desc::section_header_desc(
    const char* name, section_size size, dword flags)
    : size{std::move(size)}, flags{flags}
{
    const auto n = std::max(strlen(name + 1), (size_t)8);
    std::memcpy(this->name, name, n);
}

section_headers_builder& section_headers_builder::add(const char* name,
                                                      section_size size,
                                                      dword flags)
{
    descs_.emplace_back(name, std::move(size), flags);
    return *this;
}

section_headers section_headers_builder::build()
{
    section_headers hdrs;
    hdrs.reserve(descs_.size());

    // First section offset - based on how many section headers we defined
    dword raw = all_headers_size(descs_.size());
    dword $virtual = align(raw, SECTION_ALIGNMENT);

    for (const auto& s : descs_)
    {
        hdrs.push_back({});
        auto& header = hdrs.back();

        std::memcpy(header.Name, s.name, sizeof(s.name));
        header.Characteristics = s.flags;

        header.Misc.VirtualSize = s.size.$virtual;
        header.SizeOfRawData = align(s.size.raw, FILE_ALIGNMENT);

        header.VirtualAddress = $virtual;
        header.PointerToRawData = raw;

        $virtual = incr_check_overflow(
            $virtual, align(s.size.$virtual, SECTION_ALIGNMENT));
        raw = incr_check_overflow(raw, align(s.size.raw, FILE_ALIGNMENT));
    }

    return hdrs;
}

void pe_writer::write_dos_header(std::ostream& file) const
{
    // Write DOS header
    IMAGE_DOS_HEADER dos_header = {};
    dos_header.e_magic = 0x5A4D; // MZ
    // Some constants needed only when run in DOS mode
    dos_header.e_cblp = 0x0090;
    dos_header.e_cp = 0x0003;
    dos_header.e_cparhdr = 0x0004;
    dos_header.e_maxalloc = 0xFFFF;
    dos_header.e_sp = 0x00B8;
    dos_header.e_lfarlc = 0x0040;
    dos_header.e_lfanew = 0x00000080; // Offset for PE header
    write_bytes(file, dos_header);

    // Write DOS stub
    write_bytes(file, dos_stub);
}

void pe_writer::write_nt_headers(std::ostream& file,
                                 const section_headers& sec_headers) const
{
    IMAGE_NT_HEADERS64 nt_headers = {};
    nt_headers.Signature = 0x00004550; // PE,0,0

    auto& file_header = nt_headers.FileHeader;
    file_header.Machine = IMAGE_FILE_MACHINE_AMD64;
    file_header.NumberOfSections = static_cast<word>(sec_headers.size());
    file_header.TimeDateStamp = static_cast<dword>(time(nullptr));
    file_header.PointerToSymbolTable = 0;
    file_header.NumberOfSymbols = 0;
    file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    file_header.Characteristics = IMAGE_FILE_RELOCS_STRIPPED |
                                  IMAGE_FILE_EXECUTABLE_IMAGE |
                                  IMAGE_FILE_LARGE_ADDRESS_AWARE;

    auto& opt_header = nt_headers.OptionalHeader;
    opt_header.Magic = 0x020B; // PE32+
    opt_header.MajorLinkerVersion = 1;
    opt_header.MinorLinkerVersion = 0;
    opt_header.SizeOfCode = sec_headers[text].SizeOfRawData;
    opt_header.SizeOfInitializedData =
        sec_headers[data].SizeOfRawData + sec_headers[idata].SizeOfRawData;
    opt_header.SizeOfUninitializedData = 0;
    opt_header.AddressOfEntryPoint =
        sec_headers[text].VirtualAddress; // RVA of first intruction
    opt_header.BaseOfCode = sec_headers[text].VirtualAddress;
    opt_header.ImageBase = 0x140000000; // 0x00400000;
    opt_header.SectionAlignment =
        SECTION_ALIGNMENT; // align section virtual addresses to 4096 bytes
    opt_header.FileAlignment =
        FILE_ALIGNMENT; // align section file offsets to 512 bytes
    opt_header.MajorOperatingSystemVersion = OS_MAJOR;
    opt_header.MinorOperatingSystemVersion = OS_MINOR;
    opt_header.MajorImageVersion = OS_MAJOR;
    opt_header.MinorImageVersion = OS_MINOR;
    opt_header.MajorSubsystemVersion = OS_MAJOR;
    opt_header.MinorSubsystemVersion = OS_MINOR;
    opt_header.Win32VersionValue = 0;
    opt_header.SizeOfImage = align(sec_headers.back().VirtualAddress +
                                       sec_headers.back().Misc.VirtualSize,
                                   SECTION_ALIGNMENT);
    opt_header.SizeOfHeaders = align(all_headers_size(sec_headers.size()),
                                     FILE_ALIGNMENT); // padded
    opt_header.CheckSum = 0; // Required only for drivers
    opt_header.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    opt_header.DllCharacteristics = 0;
    opt_header.SizeOfStackReserve = 0x00100000;
    opt_header.SizeOfStackCommit = 0x00010000;
    opt_header.SizeOfHeapReserve = 0x00100000;
    opt_header.SizeOfHeapCommit = 0x00001000;
    opt_header.LoaderFlags = 0;
    opt_header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    const auto idata_addr = sec_headers[idata].VirtualAddress;
    // Informations of dll-procedure dependencies
    opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        imports_->import_dir_size();
    opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
        idata_addr + imports_->iat_size();
    // This is are where OS patches extern (dll) procedure addresses
    opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress =
        idata_addr;
    opt_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size =
        imports_->iat_size();

    write_bytes(file, nt_headers);

    for (const auto& header : sec_headers)
        write_bytes(file, header);
}

void pe_writer::write(const char* filename)
{
    const auto section_headers =
        section_headers_builder{}
            .add(".text", {code_gen_->code_size()}, SECTION_FLAGS[text])
            .add(".data", {datas_->virtual_size(), datas_->raw_size()},
                 SECTION_FLAGS[data])
            .add(".idata", {imports_->total_size()}, SECTION_FLAGS[idata])
            .build();

    // fix RVA (we now know were each section starts and ends)
    code_gen_->set_rva(section_headers[text].VirtualAddress);
    datas_->set_rva(section_headers[data].VirtualAddress);
    imports_->set_rva(section_headers[idata].VirtualAddress);

    // Generated here because if anyone of them throw we won't create a file
    const auto code = code_gen_->build();
    const auto data = datas_->build();
    const auto import = imports_->build();

    std::ofstream file{filename, std::ios::binary | std::ios::out};
    const auto err_mask = std::ifstream::failbit;
    file.exceptions(err_mask);

    write_dos_header(file);
    write_nt_headers(file, section_headers);

    // Finally, write each section with generated binary data
    write_section(file, code);
    write_section(file, data);
    write_section(file, import);
}

void pe_writer::write_section(std::ostream& strm,
                              const vector<byte>& bytes) const
{
    strm.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    const auto size = static_cast<dword>(bytes.size());
    for (dword i = size; i < align(size, FILE_ALIGNMENT); ++i)
        strm << 0_b;
}
