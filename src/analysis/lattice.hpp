#pragma once
#include <variant>
#include <cstdint>
#include <compare>

namespace Analysis {

    struct Top {
        bool operator==(const Top&) const = default;
    };
    struct Bottom {
        bool operator==(const Bottom&) const = default;
    };

    // Represents a concrete integer constant (for vtable addresses)
    struct Constant {
        uint64_t value;
        bool operator==(const Constant&) const = default;
    };

    // Represents a symbolic pointer: Base + Offset
    // Base is abstract (e.g., "The 'this' pointer of the current class")
    struct SymbolicPtr {
        int64_t offset;
        bool operator==(const SymbolicPtr&) const = default;
    };

    // The unified abstract value
    using LatticeValue = std::variant<Top, Bottom, Constant, SymbolicPtr>;

    class Lattice {
    public:
        static LatticeValue meet(const LatticeValue& a, const LatticeValue& b) {
            // Top is identity for meet
            if (std::holds_alternative<Top>(a)) return b;
            if (std::holds_alternative<Top>(b)) return a;

            // Bottom dominates
            if (std::holds_alternative<Bottom>(a) || std::holds_alternative<Bottom>(b)) return Bottom{};

            // Constant Meet
            if (std::holds_alternative<Constant>(a) && std::holds_alternative<Constant>(b)) {
                const auto& ca = std::get<Constant>(a);
                const auto& cb = std::get<Constant>(b);
                if (ca.value == cb.value) return ca;
                return Bottom{};
            }

            // Symbolic Pointer Meet
            if (std::holds_alternative<SymbolicPtr>(a) && std::holds_alternative<SymbolicPtr>(b)) {
                const auto& sa = std::get<SymbolicPtr>(a);
                const auto& sb = std::get<SymbolicPtr>(b);
                if (sa.offset == sb.offset) return sa;
                return Bottom{};
            }

            // Mismatched types -> Bottom
            return Bottom{};
        }
    };
}
