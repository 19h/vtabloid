#pragma once
#include "cfg.hpp"
#include "lattice.hpp"
#include "vtable_scanner.hpp"
#include "../common/loader.hpp"
#include <array>
#include <vector>
#include <cstdint>

namespace Analysis {

    // 16 GPRs + 16 XMMs
    constexpr int TRACKED_REG_COUNT = 32;

    struct RegisterState {
        std::array<LatticeValue, TRACKED_REG_COUNT> regs;
        // Heuristic alias tracking for the implicit 'this' pointer.
        // 1 = register may alias 'this' (seeded at function entries: RDI (SysV), RCX (MSVC)).
        std::array<uint8_t, TRACKED_REG_COUNT> this_like;

        RegisterState() {
            for (auto& r : regs) r = Top{};
            for (auto& b : this_like) b = 0;
        }

        bool operator==(const RegisterState& other) const {
            return regs == other.regs && this_like == other.this_like;
        }

        bool operator!=(const RegisterState& other) const {
            return !(*this == other);
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
        DataFlowEngine(const CFG& cfg, const Common::BinaryLoader& loader, const std::vector<VTableInfo>& vtables);
        void run();
        const std::vector<Assignment>& assignments() const { return assignments_; }

    private:
        RegisterState transfer(const BasicBlock& block, const RegisterState& in_state);
        RegisterState meet(const std::vector<uint32_t>& pred_ids);

        int map_reg(unsigned int reg_id) const;
        void scan_linear_fallback();
        void process_instruction(const Instruction& instr, RegisterState& state, bool is_heuristic);

        // Seed 'this' aliases at function entries (RDI for SysV, RCX for MSVC).
        void seed_this_alias(RegisterState& st) const;

        const CFG& cfg_;
        const Common::BinaryLoader& loader_;
        uint64_t image_base_;
        std::vector<uint64_t> vtable_vas_;

        std::vector<RegisterState> block_in_states_;
        std::vector<RegisterState> block_out_states_;

        std::vector<Assignment> assignments_;
    };
}
