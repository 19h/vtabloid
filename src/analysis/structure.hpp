#pragma once
#include "cfg.hpp"
#include "lattice.hpp"
#include "vtable_scanner.hpp"
#include "dataflow.hpp"
#include <map>
#include <set>
#include <vector>
#include <optional>

namespace Analysis {

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

    // Symbolic Pointer: Base + Offset
    struct ComplexSymbolicPtr {
        int64_t offset;
        enum class BaseType { This, Stack, Unknown } base_type;
        bool operator==(const ComplexSymbolicPtr&) const = default;
    };

    using StructValue = std::variant<Top, Bottom, Constant, ComplexSymbolicPtr>;

    // Stack Memory: Offset from Entry RSP -> Value
    using StackFrame = std::map<int64_t, StructValue>;

    struct StructState {
        std::array<StructValue, TRACKED_REG_COUNT> regs;
        StackFrame stack;
        int64_t rsp_delta; // Current RSP offset relative to Entry RSP

        StructState();
        bool operator==(const StructState& other) const;
        bool operator!=(const StructState& other) const;
    };

    class StructureAnalyzer {
    public:
        StructureAnalyzer(const CFG& cfg, const PE::PELoader& loader);

        void analyze_vtables(const std::vector<VTableInfo>& vtables);
        void analyze_constructors(const std::vector<Assignment>& assignments);

        const std::map<uint64_t, ClassLayout>& get_layouts() const { return layouts_; }

    private:
        // Core Analysis
        void analyze_function(Common::RVA start_rva, uint64_t vtable_context);

        // Lattice Operations
        StructState transfer(const BasicBlock& block, const StructState& in_state, uint64_t vtable_context);
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
        std::map<uint32_t, uint32_t> rva_to_block_id_;
    };
}
