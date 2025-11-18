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

    struct FieldAccess {
        int64_t offset;
        uint32_t size;
        bool is_write;
        Common::RVA instruction_addr;
        std::string context;
        bool is_array_access;
        bool is_vector_op;
    };

    struct ClassLayout {
        uint64_t vtable_va;
        std::vector<FieldAccess> fields;
    };

    using StackMemory = std::map<int64_t, LatticeValue>;

    constexpr int REG_COUNT_GPR = 16;
    constexpr int REG_COUNT_XMM = 16;
    constexpr int TOTAL_REG_COUNT = REG_COUNT_GPR + REG_COUNT_XMM;

    struct StructState {
        std::array<LatticeValue, TOTAL_REG_COUNT> regs;
        StackMemory stack;
        int64_t rsp_delta;

        StructState();
        bool operator==(const StructState& other) const;
        bool operator!=(const StructState& other) const;
    };

    class StructureAnalyzer {
    public:
        StructureAnalyzer(const CFG& cfg, const Common::BinaryLoader& loader);

        void analyze_vtables(const std::vector<VTableInfo>& vtables);
        void analyze_constructors(const std::vector<Assignment>& assignments);

        const std::map<uint64_t, ClassLayout>& get_layouts() const { return layouts_; }

    private:
        struct Context {
            uint64_t vtable_va;
            bool is_constructor;
        };

        void analyze_function(Common::RVA start_rva, Context ctx);

        StructState transfer(const BasicBlock& block, const StructState& in_state, const Context& ctx);
        StructState meet(const std::vector<uint32_t>& pred_ids, const std::vector<StructState>& block_out_states);

        void handle_mov(const Instruction& instr, StructState& state, const Context& ctx);
        void handle_lea(const Instruction& instr, StructState& state);
        void handle_arithmetic(const Instruction& instr, StructState& state);
        void handle_stack_op(const Instruction& instr, StructState& state);
        void handle_logic(const Instruction& instr, StructState& state);

        int map_reg(unsigned int reg_id) const;
        void record_access(uint64_t vtable_va, int64_t offset, uint32_t size, bool is_write,
                           Common::RVA addr, const std::string& ctx, bool is_array, bool is_vector);

        Common::RVA find_function_start(Common::RVA instr_addr) const;

        const CFG& cfg_;
        const Common::BinaryLoader& loader_;

        std::map<uint64_t, ClassLayout> layouts_;
        std::set<uint32_t> processed_functions_;
        std::map<uint32_t, uint32_t> rva_to_block_id_;
    };
}
