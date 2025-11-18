#pragma once
#include "../common/loader.hpp"
#include "macho_structures.hpp"

namespace MachO {

    class MachoLoader : public Common::BinaryLoader {
    public:
        explicit MachoLoader(const std::string& filepath);
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
        bool load_fat(const std::vector<uint8_t>& raw_data);
        bool load_thin(const std::vector<uint8_t>& raw_data);

        // Helper to swap bytes if needed
        uint32_t swap32(uint32_t val) const;

        std::string filepath_;
        std::vector<uint8_t> buffer_; // Stores the active slice (or whole file if thin)
        std::unique_ptr<Common::BinaryView> view_;
        std::vector<Common::Section> sections_;
        Common::RVA entry_point_{0};
        Common::Arch arch_{Common::Arch::x64}; // We only support x64 slice for now
        uint64_t image_base_{0};
        bool is_big_endian_{false};
    };
}
