#pragma once
#include <cstdint>
#include <compare>
#include <limits>
#include <string>
#include <format>

namespace Common {

    // Strongly typed Relative Virtual Address
    struct RVA {
        uint32_t value;
        constexpr auto operator<=>(const RVA&) const = default;

        RVA operator+(uint32_t offset) const { return RVA{value + offset}; }
        RVA operator-(uint32_t offset) const { return RVA{value - offset}; }
        uint32_t operator-(RVA other) const { return value - other.value; }

        explicit operator bool() const { return value != 0; }
    };

    // Strongly typed File Offset
    struct FileOffset {
        uint32_t value;
        constexpr auto operator<=>(const FileOffset&) const = default;

        FileOffset operator+(uint32_t offset) const { return FileOffset{value + offset}; }
        FileOffset operator-(uint32_t offset) const { return FileOffset{value - offset}; }
    };

    constexpr uint32_t INVALID_ADDR = std::numeric_limits<uint32_t>::max();

    enum class Arch {
        x86,
        x64
    };
}
