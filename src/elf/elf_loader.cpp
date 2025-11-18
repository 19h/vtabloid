#include "elf_loader.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>

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

        // Temporary view to read headers
        Common::BinaryView raw_view(buffer_, 0);

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

        image_base_ = 0;

        auto sh_offset = Common::FileOffset{static_cast<uint32_t>(hdr->e_shoff)};

        if (hdr->e_shstrndx >= hdr->e_shnum) return false;

        // Cache all section headers
        shdr64_.clear();
        shdr64_.reserve(hdr->e_shnum);
        for (uint16_t i = 0; i < hdr->e_shnum; ++i) {
            auto sec_off = sh_offset + (static_cast<uint32_t>(i) * static_cast<uint32_t>(hdr->e_shentsize));
            auto shdr = raw_view.read<Elf64_Shdr>(sec_off);
            if (!shdr) return false;
            shdr64_.push_back(*shdr);
        }

        auto strtab_hdr = shdr64_[hdr->e_shstrndx];
        Common::FileOffset strtab_off{static_cast<uint32_t>(strtab_hdr.sh_offset)};

        // First Pass: Apply relocations (RELATIVE, GLOB_DAT, JUMP_SLOT, 64)
        for (uint16_t i = 0; i < hdr->e_shnum; ++i) {
            const auto& s = shdr64_[i];
            if (s.sh_type == SHT_RELA) {
                apply_relocations_64(s);
            }
        }

        // Second Pass: Create Sections and Parse Symbols
        for (uint16_t i = 0; i < hdr->e_shnum; ++i) {
            const auto& s = shdr64_[i];

            Common::Section sec;
            auto name_res = raw_view.read_string(strtab_off + s.sh_name);
            sec.name = name_res.value_or("");

            sec.raw_ptr = Common::FileOffset{static_cast<uint32_t>(s.sh_offset)};
            sec.raw_size = static_cast<uint32_t>(s.sh_size);
            sec.virtual_size = static_cast<uint32_t>(s.sh_size);
            sec.rva = Common::RVA{static_cast<uint32_t>(s.sh_addr)};

            sec.is_executable = (s.sh_flags & SHF_EXECINSTR) != 0;
            sec.is_writable   = (s.sh_flags & SHF_WRITE) != 0;
            sec.is_readable   = (s.sh_flags & SHF_ALLOC) != 0;

            if (s.sh_flags & SHF_ALLOC) {
                sections_.push_back(sec);
            }

            if (s.sh_type == SHT_SYMTAB || s.sh_type == SHT_DYNSYM) {
                parse_symbols_64(s, raw_view);
            }
            if (s.sh_type == SHT_INIT_ARRAY) {
                parse_init_array_64(s);
            }
        }

        entry_point_ = Common::RVA{static_cast<uint32_t>(hdr->e_entry - image_base_)};

        for (auto& sec : sections_) {
            sec.rva = Common::RVA{sec.rva.value - static_cast<uint32_t>(image_base_)};
        }

        view_ = std::make_unique<Common::BinaryView>(buffer_, image_base_);
        return true;
    }

    bool ELFLoader::va_to_file_off_64(uint64_t va, uint64_t& file_off) const {
        for (const auto& s : shdr64_) {
            if (va >= s.sh_addr && va < s.sh_addr + s.sh_size) {
                file_off = s.sh_offset + (va - s.sh_addr);
                return true;
            }
        }
        return false;
    }

    void ELFLoader::apply_relocations_64(const Elf64_Shdr& rela_shdr) {
        const uint32_t target_sec_idx = static_cast<uint32_t>(rela_shdr.sh_info);
        if (target_sec_idx >= shdr64_.size()) return;

        const uint32_t symtab_idx = static_cast<uint32_t>(rela_shdr.sh_link);
        const bool has_symtab = symtab_idx < shdr64_.size() &&
                                (shdr64_[symtab_idx].sh_type == SHT_SYMTAB || shdr64_[symtab_idx].sh_type == SHT_DYNSYM);

        const uint64_t rela_count = rela_shdr.sh_size / sizeof(Elf64_Rela);
        uint64_t rela_off = rela_shdr.sh_offset;

        for (uint64_t i = 0; i < rela_count; ++i) {
            if (rela_off + (i + 1) * sizeof(Elf64_Rela) > buffer_.size()) break;

            Elf64_Rela rela;
            std::memcpy(&rela, buffer_.data() + rela_off + (i * sizeof(Elf64_Rela)), sizeof(Elf64_Rela));

            const uint32_t type = ELF64_R_TYPE(rela.r_info);
            const uint32_t sym_index = ELF64_R_SYM(rela.r_info);

            uint64_t place_file_off = 0;
            if (!va_to_file_off_64(rela.r_offset, place_file_off)) continue;

            uint64_t value = 0;
            bool write_val = false;

            if (type == R_X86_64_RELATIVE) {
                value = image_base_ + static_cast<uint64_t>(rela.r_addend);
                write_val = true;
            } else if (type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT) {
                if (!has_symtab) continue;
                Elf64_Sym sym{};
                if (!read_symbol_64(symtab_idx, sym_index, sym)) continue;
                value = sym.st_value;
                write_val = true;
            } else if (type == R_X86_64_64) {
                if (!has_symtab) continue;
                Elf64_Sym sym{};
                if (!read_symbol_64(symtab_idx, sym_index, sym)) continue;
                value = sym.st_value + static_cast<uint64_t>(rela.r_addend);
                write_val = true;
            } else {
                continue;
            }

            if (write_val && place_file_off + 8 <= buffer_.size()) {
                std::memcpy(buffer_.data() + place_file_off, &value, 8);
            }
        }
    }

    bool ELFLoader::read_symbol_64(uint32_t symtab_idx, uint32_t sym_index, Elf64_Sym& out) const {
        if (symtab_idx >= shdr64_.size()) return false;
        const auto& symtab = shdr64_[symtab_idx];
        if (sym_index == 0) return false; // STN_UNDEF
        const uint64_t entsz = symtab.sh_entsize ? symtab.sh_entsize : sizeof(Elf64_Sym);
        const uint64_t off = symtab.sh_offset + static_cast<uint64_t>(sym_index) * entsz;
        if (off + sizeof(Elf64_Sym) > buffer_.size()) return false;
        std::memcpy(&out, buffer_.data() + off, sizeof(Elf64_Sym));
        return true;
    }

    void ELFLoader::parse_symbols_64(const Elf64_Shdr& shdr, const Common::BinaryView& raw_view) {
        size_t count = shdr.sh_size / sizeof(Elf64_Sym);
        uint32_t offset = static_cast<uint32_t>(shdr.sh_offset);

        for (size_t i = 0; i < count; ++i) {
            auto sym = raw_view.read<Elf64_Sym>(Common::FileOffset{offset + static_cast<uint32_t>(i * sizeof(Elf64_Sym))});
            if (!sym) break;

            // STT_FUNC = 2
            if ((sym->st_info & 0xF) == 2 && sym->st_value != 0 && sym->st_shndx != 0) {
                function_symbols_.push_back(Common::RVA{static_cast<uint32_t>(sym->st_value - image_base_)});
            }
        }
    }

    void ELFLoader::parse_init_array_64(const Elf64_Shdr& shdr) {
        size_t count = shdr.sh_size / 8;
        uint32_t offset = static_cast<uint32_t>(shdr.sh_offset);

        for (size_t i = 0; i < count; ++i) {
            uint64_t val;
            if (offset + (i + 1) * 8 > buffer_.size()) break;
            std::memcpy(&val, buffer_.data() + offset + (i * 8), 8);

            if (val != 0) {
                global_constructors_.push_back(Common::RVA{static_cast<uint32_t>(val - image_base_)});
            }
        }
    }

    bool ELFLoader::load_32(const Common::BinaryView& raw_view) {
        auto hdr = raw_view.read<Elf32_Ehdr>(Common::FileOffset{0});
        if (!hdr) return false;

        if (hdr->e_machine != EM_386) return false;

        image_base_ = 0;

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

            Common::Section s;
            auto name_res = raw_view.read_string(strtab_off + shdr->sh_name);
            s.name = name_res.value_or("");
            s.raw_ptr = Common::FileOffset{shdr->sh_offset};
            s.raw_size = shdr->sh_size;
            s.virtual_size = shdr->sh_size;
            s.rva = Common::RVA{shdr->sh_addr};

            s.is_executable = (shdr->sh_flags & SHF_EXECINSTR) != 0;
            s.is_writable   = (shdr->sh_flags & SHF_WRITE) != 0;
            s.is_readable   = (shdr->sh_flags & SHF_ALLOC) != 0;

            if (shdr->sh_flags & SHF_ALLOC) {
                sections_.push_back(s);
            }
        }

        entry_point_ = Common::RVA{static_cast<uint32_t>(hdr->e_entry)};

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
