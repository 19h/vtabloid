#include "pe_loader.hpp"
#include <fstream>
#include <iostream>
#include <cstring>

namespace PE {

    PELoader::PELoader(const std::string& filepath) : filepath_(filepath) {}

    bool PELoader::load() {
        std::ifstream file(filepath_, std::ios::binary | std::ios::ate);
        if (!file) return false;

        auto size = file.tellg();
        if (size <= 0) return false;

        buffer_.resize(static_cast<size_t>(size));
        file.seekg(0);
        file.read(reinterpret_cast<char*>(buffer_.data()), size);

        Common::BinaryView raw_view(buffer_, 0);

        auto dos = raw_view.read<IMAGE_DOS_HEADER>(Common::FileOffset{0});
        if (!dos || dos->e_magic != DOS_MAGIC) return false;

        auto nt_offset = Common::FileOffset{dos->e_lfanew};
        auto nt_sig = raw_view.read<uint32_t>(nt_offset);
        if (!nt_sig || *nt_sig != PE_MAGIC) return false;

        auto file_hdr = raw_view.read<IMAGE_FILE_HEADER>(nt_offset + 4);
        if (!file_hdr) return false;

        uint64_t image_base = 0;
        uint32_t entry_point = 0;
        auto opt_offset = nt_offset + 4 + sizeof(IMAGE_FILE_HEADER);

        if (file_hdr->Machine == MACHINE_AMD64) {
            arch_ = Common::Arch::x64;
            auto opt = raw_view.read<IMAGE_OPTIONAL_HEADER64>(opt_offset);
            if (!opt) return false;
            image_base = opt->ImageBase;
            entry_point = opt->AddressOfEntryPoint;

            if (opt->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
                exception_dir_ = {
                    Common::RVA{opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress},
                    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size
                };
            }

        } else if (file_hdr->Machine == MACHINE_I386) {
            arch_ = Common::Arch::x86;
            auto opt = raw_view.read<IMAGE_OPTIONAL_HEADER32>(opt_offset);
            if (!opt) return false;
            image_base = opt->ImageBase;
            entry_point = opt->AddressOfEntryPoint;
        } else {
            return false;
        }

        view_ = std::make_unique<Common::BinaryView>(buffer_, image_base);
        entry_point_ = Common::RVA{entry_point};

        auto section_offset = opt_offset + file_hdr->SizeOfOptionalHeader;
        for (uint32_t i = 0; i < file_hdr->NumberOfSections; ++i) {
            uint32_t current_sec_offset = section_offset.value + (i * static_cast<uint32_t>(sizeof(IMAGE_SECTION_HEADER)));
            auto sec_hdr = raw_view.read<IMAGE_SECTION_HEADER>(Common::FileOffset{current_sec_offset});
            if (!sec_hdr) break;

            Common::Section s;
            char name[9] = {0};
            std::memcpy(name, sec_hdr->Name, 8);
            s.name = name;
            s.rva = Common::RVA{sec_hdr->VirtualAddress};
            s.virtual_size = sec_hdr->VirtualSize;
            s.raw_ptr = Common::FileOffset{sec_hdr->PointerToRawData};
            s.raw_size = sec_hdr->SizeOfRawData;

            s.is_executable = (sec_hdr->Characteristics & SCN_MEM_EXECUTE) != 0;
            s.is_readable   = (sec_hdr->Characteristics & SCN_MEM_READ) != 0;
            s.is_writable   = (sec_hdr->Characteristics & SCN_MEM_WRITE) != 0;

            sections_.push_back(s);
        }
        return true;
    }

    std::optional<Common::FileOffset> PELoader::rva_to_offset(Common::RVA rva) const {
        for (const auto& sec : sections_) {
            if (sec.contains(rva)) {
                uint32_t delta = rva.value - sec.rva.value;
                if (delta < sec.raw_size) return sec.raw_ptr + delta;
            }
        }
        return std::nullopt;
    }

    std::optional<Common::RVA> PELoader::offset_to_rva(Common::FileOffset offset) const {
        for (const auto& sec : sections_) {
            if (offset.value >= sec.raw_ptr.value && offset.value < sec.raw_ptr.value + sec.raw_size) {
                return sec.rva + (offset.value - sec.raw_ptr.value);
            }
        }
        return std::nullopt;
    }

    std::optional<uint64_t> PELoader::read_ptr_at(Common::RVA rva) const {
        auto off = rva_to_offset(rva);
        if (!off) return std::nullopt;
        return view_->read_ptr(*off, arch_);
    }
}
