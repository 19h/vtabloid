#pragma once
#include <vector>
#include <set>
#include <map>
#include <memory>
#include "../pe/pe_loader.hpp"
#include <capstone/capstone.h>

namespace Analysis {

    struct Instruction {
        Common::RVA address;
        uint32_t size;
        std::string mnemonic;
        std::string op_str;
        unsigned int id;
        cs_x86_op operands[8];
        uint8_t op_count;

        bool is_call() const {
            return id == X86_INS_CALL;
        }
        bool is_ret() const {
            return id == X86_INS_RET;
        }
        bool is_jump() const {
            // Robust check for conditional jumps using Capstone IDs
            // We exclude unconditional jumps (JMP, LJMP) to identify Jcc
            return (id >= X86_INS_JAE && id <= X86_INS_JS) ||
                   (id == X86_INS_JECXZ) || (id == X86_INS_JRCXZ);
        }
        bool is_unconditional_jump() const {
            return id == X86_INS_JMP;
        }
    };

    struct BasicBlock {
        uint32_t id;
        Common::RVA start_address;
        Common::RVA end_address;
        std::vector<Instruction> instructions;
        std::vector<uint32_t> succ_ids;
        std::vector<uint32_t> pred_ids;

        bool is_terminated_by_ret() const {
            if (instructions.empty()) return false;
            return instructions.back().is_ret();
        }
    };

    class CFG {
    public:
        explicit CFG(const PE::PELoader& loader);
        ~CFG();

        void build();
        const std::vector<std::shared_ptr<BasicBlock>>& get_blocks() const { return linear_blocks_; }
        const std::vector<Common::RVA>& functions() const { return function_entries_; }

    private:
        void discover_functions();
        void disassemble_recursive(Common::RVA start);
        void handle_jump_table(const Instruction& instr, Common::RVA current_pc);
        void linearize_graph();

        const PE::PELoader& loader_;
        csh cs_handle_;
        std::map<uint32_t, std::shared_ptr<BasicBlock>> rva_to_block_;
        std::vector<std::shared_ptr<BasicBlock>> linear_blocks_;
        std::vector<Common::RVA> function_entries_;
        std::set<uint32_t> visited_instructions_;

        std::map<uint32_t, std::vector<Common::RVA>> indirect_jumps_;
    };
}