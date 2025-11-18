#pragma once
#include "cfg.hpp"
#include "lattice.hpp"
#include "vtable_scanner.hpp"
#include <array>
#include <vector>

namespace Analysis {

    constexpr int TRACKED_REG_COUNT = 16;

    struct RegisterState {
        std::array<LatticeValue, TRACKED_REG_COUNT> regs;

        RegisterState() {
            for(auto& r : regs) r = Top{};
        }

        bool operator==(const RegisterState& other) const {
            return regs == other.regs;
        }

        bool operator!=(const RegisterState& other) const {
            return regs != other.regs;
        }
    };

    struct Assignment {
        Common::RVA addr;
        uint64_t vtable_va;
        std::string desc;
        bool is_heuristic;
    };

    class DataFlowEngine {
    public:
        DataFlowEngine(const CFG& cfg, const std::vector<VTableInfo>& vtables, uint64_t image_base);
        void run();
        const std::vector<Assignment>& assignments() const { return assignments_; }

    private:
        RegisterState transfer(const BasicBlock& block, const RegisterState& in_state);
        RegisterState meet(const std::vector<uint32_t>& pred_ids);

        int map_reg(unsigned int reg_id) const;
        void scan_linear_fallback();
        void process_instruction(const Instruction& instr, RegisterState& state, bool is_heuristic);

        const CFG& cfg_;
        uint64_t image_base_;
        std::vector<uint64_t> vtable_vas_;

        std::vector<RegisterState> block_in_states_;
        std::vector<RegisterState> block_out_states_;

        std::vector<Assignment> assignments_;
    };
}