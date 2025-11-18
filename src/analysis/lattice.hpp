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

    struct Constant {
        uint64_t value;
        bool operator==(const Constant&) const = default;
    };

    // Unified Symbolic Pointer for both DataFlow and Structure Analysis
    struct SymbolicPtr {
        enum class Base {
            This,       // The object instance
            Stack,      // The stack frame
            Global,     // Global data
            Unknown
        } type;

        int64_t offset;
        uint64_t bound_vtable; // 0 if unbound

        bool operator==(const SymbolicPtr&) const = default;
    };

    using LatticeValue = std::variant<Top, Bottom, Constant, SymbolicPtr>;

    class Lattice {
    public:
        static LatticeValue meet(const LatticeValue& a, const LatticeValue& b) {
            if (std::holds_alternative<Top>(a)) return b;
            if (std::holds_alternative<Top>(b)) return a;
            if (std::holds_alternative<Bottom>(a) || std::holds_alternative<Bottom>(b)) return Bottom{};

            if (std::holds_alternative<Constant>(a) && std::holds_alternative<Constant>(b)) {
                const auto& ca = std::get<Constant>(a);
                const auto& cb = std::get<Constant>(b);
                if (ca.value == cb.value) return ca;
                return Bottom{};
            }

            if (std::holds_alternative<SymbolicPtr>(a) && std::holds_alternative<SymbolicPtr>(b)) {
                const auto& sa = std::get<SymbolicPtr>(a);
                const auto& sb = std::get<SymbolicPtr>(b);
                if (sa.type == sb.type && sa.offset == sb.offset && sa.bound_vtable == sb.bound_vtable) return sa;
                return Bottom{};
            }

            return Bottom{};
        }
    };
}