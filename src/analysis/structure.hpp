#pragma once
#include "cfg.hpp"
#include "lattice.hpp"
#include "vtable_scanner.hpp"
#include "dataflow.hpp"
#include <map>
#include <set>
#include <vector>
#include <optional>
#include <variant>
#include <array>

namespace Analysis {

    // Represents a discovered field in a class
    struct FieldAccess {
        int64_t offset;
        uint32_t size;
        bool is_write;
        Common::RVA instruction_addr;
        std::string context;
    };

    struct ClassLayout {
        uint64_t vtable_va;
        std::vector<FieldAccess> fields;
    };

    // --- Abstract Domain for Structure Inference ---

    // Symbolic Pointer: Base + Offset
    struct ComplexSymbolicPtr {
        int64_t offset;
        // 'This' refers to the object instance being analyzed.
        // 'Stack' refers to the current function's stack frame (relative to Entry RSP).
        enum class BaseType { This, Stack, Unknown } base_type;

        // If we know WHICH vtable this pointer is bound to (e.g. after an assignment), we track it.
        // 0 means unbound (generic 'this').
        uint64_t bound_vtable;

        bool operator==(const ComplexSymbolicPtr&) const = default;
    };

    // Re-using Top/Bottom/Constant from lattice.hpp, adding ComplexSymbolicPtr
    using StructValue = std::variant<Top, Bottom, Constant, ComplexSymbolicPtr>;

    // Stack Memory: Offset from Entry RSP -> Value
    // This allows us to track spills of 'this' to the stack.
    using StackFrame = std::map<int64_t, StructValue>;

    struct StructState {
        std::array<StructValue, TRACKED_REG_COUNT> regs;
        StackFrame stack;
        int64_t rsp_delta; // Current RSP offset relative to Function Entry RSP

        StructState();
        bool operator==(const StructState& other) const;
        bool operator!=(const StructState& other) const;
    };

    class StructureAnalyzer {
    public:
        StructureAnalyzer(const CFG& cfg, const PE::PELoader& loader);

        // Primary entry point: Analyze functions that contain vtable assignments
        void analyze_constructors(const std::vector<Assignment>& assignments);

        const std::map<uint64_t, ClassLayout>& get_layouts() const { return layouts_; }

    private:
        // Analysis Core
        void analyze_function(Common::RVA start_rva, const std::set<uint64_t>& interesting_vtables);

        // Transfer Function
        StructState transfer(const BasicBlock& block, const StructState& in_state, const std::set<uint64_t>& interesting_vtables);

        // Meet Operator
        StructState meet(const std::vector<uint32_t>& pred_ids, const std::vector<StructState>& block_out_states);
        static StructValue meet_value(const StructValue& a, const StructValue& b);

        // Helpers
        int map_reg(unsigned int reg_id) const;
        void record_access(uint64_t vtable_va, int64_t offset, uint32_t size, bool is_write, Common::RVA addr, const std::string& ctx);
        Common::RVA find_function_start(Common::RVA instr_addr) const;

        const CFG& cfg_;
        const PE::PELoader& loader_;

        std::map<uint64_t, ClassLayout> layouts_;
        std::set<uint32_t> processed_functions_;

        // Fast lookup for CFG navigation
        std::map<uint32_t, uint32_t> rva_to_block_id_;
    };
}
