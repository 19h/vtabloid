#pragma once
#include "../common/loader.hpp"
#include "elf_structures.hpp"
#include <map>
#include <vector>

namespace ELF {

    class ELFLoader : public Common::BinaryLoader {
    public:
        explicit ELFLoader(const std::string& filepath);
        bool load() override;

        std::optional<Common::FileOffset> rva_to_offset(Common::RVA rva) const override;
        std::optional<Common::RVA> offset_to_rva(Common::FileOffset offset) const override;
        std::optional<uint64_t> read_ptr_at(Common::RVA rva) const override;

        const std::vector<Common::Section>& sections() const override { return sections_; }
        const Common::BinaryView& view() const override { return *view_; }
        Common::RVA entry_point() const override { return entry_point_; }
        Common::Arch architecture() const override { return arch_; }
        bool is_64bit() const override { return arch_ == Common::Arch::x64; }

    private:
        bool load_32(const Common::BinaryView& raw_view);
        bool load_64(const Common::BinaryView& raw_view);

        // Relocations (ELF64)
        void apply_relocations_64(const Elf64_Shdr& shdr);
        bool read_symbol_64(uint32_t symtab_idx, uint32_t sym_index, Elf64_Sym& out) const;
        bool va_to_file_off_64(uint64_t va, uint64_t& file_off) const;

        void parse_symbols_64(const Elf64_Shdr& shdr, const Common::BinaryView& raw_view);
        void parse_init_array_64(const Elf64_Shdr& shdr);

        std::string filepath_;
        std::vector<uint8_t> buffer_;
        std::unique_ptr<Common::BinaryView> view_;
        std::vector<Common::Section> sections_;
        Common::RVA entry_point_{0};
        Common::Arch arch_{Common::Arch::x86};
        uint64_t image_base_{0};

        // Cached ELF64 section headers for relocation/symbol decoding
        std::vector<Elf64_Shdr> shdr64_;
    };
}
