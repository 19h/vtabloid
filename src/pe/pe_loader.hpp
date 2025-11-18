#pragma once
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "../common/types.hpp"
#include "../common/binary_view.hpp"
#include "pe_structures.hpp"

namespace PE {

    struct Section {
        std::string name;
        Common::RVA rva;
        uint32_t virtual_size;
        Common::FileOffset raw_ptr;
        uint32_t raw_size;
        uint32_t characteristics;

        [[nodiscard]] bool is_executable() const { return characteristics & SCN_MEM_EXECUTE; }
        [[nodiscard]] bool is_readable() const { return characteristics & SCN_MEM_READ; }
        [[nodiscard]] bool is_writable() const { return characteristics & SCN_MEM_WRITE; }

        [[nodiscard]] bool contains(Common::RVA addr) const {
            return addr.value >= rva.value && addr.value < rva.value + virtual_size;
        }
    };

    class PELoader {
    public:
        explicit PELoader(const std::string& filepath);
        bool load();

        [[nodiscard]] std::optional<Common::FileOffset> rva_to_offset(Common::RVA rva) const;
        [[nodiscard]] std::optional<Common::RVA> offset_to_rva(Common::FileOffset offset) const;

        // Helper to read a pointer from an RVA
        [[nodiscard]] std::optional<uint64_t> read_ptr_at(Common::RVA rva) const;

        [[nodiscard]] const std::vector<Section>& sections() const { return sections_; }
        [[nodiscard]] const Common::BinaryView& view() const { return *view_; }
        [[nodiscard]] Common::RVA entry_point() const { return entry_point_; }
        [[nodiscard]] Common::Arch architecture() const { return arch_; }
        [[nodiscard]] bool is_64bit() const { return arch_ == Common::Arch::x64; }

        [[nodiscard]] std::pair<Common::RVA, uint32_t> exception_directory() const { return exception_dir_; }

    private:
        std::string filepath_;
        std::vector<uint8_t> buffer_;
        std::unique_ptr<Common::BinaryView> view_;
        std::vector<Section> sections_;
        Common::RVA entry_point_{0};
        Common::Arch arch_{Common::Arch::x86};
        std::pair<Common::RVA, uint32_t> exception_dir_{0, 0};
    };
}