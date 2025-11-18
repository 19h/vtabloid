#include "elf_loader.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>

namespace ELF {

    ELFLoader::ELFLoader(const std::string& filepath) : filepath_(filepath) {}

    bool ELFLoader::load() {
        std::ifstream file(filepath_, std::ios::binary | std::ios::ate);
        if (!file) return false;

        auto size = file.tellg();
        if (size <= 0) return false;

        buffer_.resize(static_cast<size_t>(size));
        file.seekg(0);
        file.read(reinterpret_cast<char*>(buffer_.data()), size);

        Common::BinaryView raw_view(buffer_, 0);

        // Check Magic
        auto ident = raw_view.read<std::array<uint8_t, 16>>(Common::FileOffset{0});
        if (!ident) return false;
        if ((*ident)[0] != ELFMAG0 || (*ident)[1] != ELFMAG1 ||
            (*ident)[2] != ELFMAG2 || (*ident)[3] != ELFMAG3) return false;

        uint8_t cls = (*ident)[4];
        if (cls == ELFCLASS64) {
            arch_ = Common::Arch::x64;
            return load_64(raw_view);
        } else if (cls == ELFCLASS32) {
            arch_ = Common::Arch::x86;
            return load_32(raw_view);
        }

        return false;
    }

    bool ELFLoader::load_64(const Common::BinaryView& raw_view) {
        auto hdr = raw_view.read<Elf64_Ehdr>(Common::FileOffset{0});
        if (!hdr) return false;

        if (hdr->e_machine != EM_X86_64) return false;

        // Determine Image Base (Lowest Loadable Address)
        uint64_t min_addr = UINT64_MAX;

        // Read Section Headers
        auto sh_offset = Common::FileOffset{static_cast<uint32_t>(hdr->e_shoff)};

        // Read String Table for Section Names
        if (hdr->e_shstrndx >= hdr->e_shnum) return false;

        auto strtab_hdr_off = sh_offset + (static_cast<uint32_t>(hdr->e_shstrndx) * static_cast<uint32_t>(hdr->e_shentsize));
        auto strtab_hdr = raw_view.read<Elf64_Shdr>(strtab_hdr_off);
        if (!strtab_hdr) return false;

        Common::FileOffset strtab_off{static_cast<uint32_t>(strtab_hdr->sh_offset)};

        for (uint16_t i = 0; i < hdr->e_shnum; ++i) {
            auto sec_off = sh_offset + (static_cast<uint32_t>(i) * static_cast<uint32_t>(hdr->e_shentsize));
            auto shdr = raw_view.read<Elf64_Shdr>(sec_off);
            if (!shdr) break;

            if (shdr->sh_flags & SHF_ALLOC) {
                if (shdr->sh_addr < min_addr) min_addr = shdr->sh_addr;
            }

            Common::Section s;
            auto name_res = raw_view.read_string(strtab_off + shdr->sh_name);
            s.name = name_res.value_or("");

            s.raw_ptr = Common::FileOffset{static_cast<uint32_t>(shdr->sh_offset)};
            s.raw_size = static_cast<uint32_t>(shdr->sh_size);
            s.virtual_size = static_cast<uint32_t>(shdr->sh_size);

            // Store absolute VA temporarily, adjust later
            s.rva = Common::RVA{static_cast<uint32_t>(shdr->sh_addr)};

            s.is_executable = (shdr->sh_flags & SHF_EXECINSTR) != 0;
            s.is_writable = (shdr->sh_flags & SHF_WRITE) != 0;
            s.is_readable = (shdr->sh_flags & SHF_ALLOC) != 0;

            if (shdr->sh_flags & SHF_ALLOC) {
                sections_.push_back(s);
            }
        }

        image_base_ = min_addr;
        entry_point_ = Common::RVA{static_cast<uint32_t>(hdr->e_entry - image_base_)};

        // Adjust Section RVAs to be relative to ImageBase
        for (auto& sec : sections_) {
            sec.rva = Common::RVA{sec.rva.value - static_cast<uint32_t>(image_base_)};
        }

        view_ = std::make_unique<Common::BinaryView>(buffer_, image_base_);
        return true;
    }

    bool ELFLoader::load_32(const Common::BinaryView& raw_view) {
        auto hdr = raw_view.read<Elf32_Ehdr>(Common::FileOffset{0});
        if (!hdr) return false;

        if (hdr->e_machine != EM_386) return false;

        uint64_t min_addr = UINT64_MAX;
        auto sh_offset = Common::FileOffset{hdr->e_shoff};

        if (hdr->e_shstrndx >= hdr->e_shnum) return false;
        auto strtab_hdr_off = sh_offset + (static_cast<uint32_t>(hdr->e_shstrndx) * static_cast<uint32_t>(hdr->e_shentsize));
        auto strtab_hdr = raw_view.read<Elf32_Shdr>(strtab_hdr_off);
        if (!strtab_hdr) return false;
        Common::FileOffset strtab_off{strtab_hdr->sh_offset};

        for (uint16_t i = 0; i < hdr->e_shnum; ++i) {
            auto sec_off = sh_offset + (static_cast<uint32_t>(i) * static_cast<uint32_t>(hdr->e_shentsize));
            auto shdr = raw_view.read<Elf32_Shdr>(sec_off);
            if (!shdr) break;

            if (shdr->sh_flags & SHF_ALLOC) {
                if (shdr->sh_addr < min_addr) min_addr = shdr->sh_addr;
            }

            Common::Section s;
            auto name_res = raw_view.read_string(strtab_off + shdr->sh_name);
            s.name = name_res.value_or("");
            s.raw_ptr = Common::FileOffset{shdr->sh_offset};
            s.raw_size = shdr->sh_size;
            s.virtual_size = shdr->sh_size;
            s.rva = Common::RVA{shdr->sh_addr};

            s.is_executable = (shdr->sh_flags & SHF_EXECINSTR) != 0;
            s.is_writable = (shdr->sh_flags & SHF_WRITE) != 0;
            s.is_readable = (shdr->sh_flags & SHF_ALLOC) != 0;

            if (shdr->sh_flags & SHF_ALLOC) {
                sections_.push_back(s);
            }
        }

        image_base_ = min_addr;
        entry_point_ = Common::RVA{static_cast<uint32_t>(hdr->e_entry - image_base_)};

        for (auto& sec : sections_) {
            sec.rva = Common::RVA{sec.rva.value - static_cast<uint32_t>(image_base_)};
        }

        view_ = std::make_unique<Common::BinaryView>(buffer_, image_base_);
        return true;
    }

    std::optional<Common::FileOffset> ELFLoader::rva_to_offset(Common::RVA rva) const {
        for (const auto& sec : sections_) {
            if (sec.contains(rva)) {
                uint32_t delta = rva.value - sec.rva.value;
                if (delta < sec.raw_size) return sec.raw_ptr + delta;
            }
        }
        return std::nullopt;
    }

    std::optional<Common::RVA> ELFLoader::offset_to_rva(Common::FileOffset offset) const {
        for (const auto& sec : sections_) {
            if (offset.value >= sec.raw_ptr.value && offset.value < sec.raw_ptr.value + sec.raw_size) {
                return sec.rva + (offset.value - sec.raw_ptr.value);
            }
        }
        return std::nullopt;
    }

    std::optional<uint64_t> ELFLoader::read_ptr_at(Common::RVA rva) const {
        auto off = rva_to_offset(rva);
        if (!off) return std::nullopt;
        return view_->read_ptr(*off, arch_);
    }
}
