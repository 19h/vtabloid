#pragma once
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "types.hpp"
#include "binary_view.hpp"

namespace Common {

    struct Section {
        std::string name;
        RVA rva;
        uint32_t virtual_size;
        FileOffset raw_ptr;
        uint32_t raw_size;

        bool is_executable;
        bool is_readable;
        bool is_writable;

        bool contains(RVA addr) const {
            return addr.value >= rva.value && addr.value < rva.value + virtual_size;
        }
    };

    class BinaryLoader {
    public:
        virtual ~BinaryLoader() = default;

        virtual bool load() = 0;

        virtual std::optional<FileOffset> rva_to_offset(RVA rva) const = 0;
        virtual std::optional<RVA> offset_to_rva(FileOffset offset) const = 0;
        virtual std::optional<uint64_t> read_ptr_at(RVA rva) const = 0;

        virtual const std::vector<Section>& sections() const = 0;
        virtual const BinaryView& view() const = 0;
        virtual RVA entry_point() const = 0;
        virtual Arch architecture() const = 0;
        virtual bool is_64bit() const = 0;

        // Platform specific extensions (PE only for now, returns {0,0} for ELF)
        virtual std::pair<RVA, uint32_t> exception_directory() const { return {RVA{0}, 0}; }
    };
}
