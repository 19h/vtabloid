#pragma once
#include <variant>
#include <cstdint>
#include <compare>
#include <vector>
#include <algorithm>

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

    // Enhanced Symbolic Pointer
    struct SymbolicPtr {
        enum class Base {
            This,       // The object instance (RCX in constructor)
            Stack,      // The stack frame (RSP/RBP relative)
            Global,     // Global data
            Heap,       // Return from allocator
            Unknown
        } type;

        int64_t offset;

        // History tracking for type inference
        // If we know this pointer was assigned VTable X, we track it here.
        uint64_t bound_vtable;

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

                if (sa.type == sb.type && sa.offset == sb.offset) {
                    // If vtables differ, we might be seeing a merge point of two different constructors
                    // or a base/derived confusion. For now, if they differ, we keep the pointer but lose the vtable binding.
                    SymbolicPtr res = sa;
                    if (sa.bound_vtable != sb.bound_vtable) {
                        res.bound_vtable = 0;
                    }
                    return res;
                }
                return Bottom{};
            }

            return Bottom{};
        }
    };
}