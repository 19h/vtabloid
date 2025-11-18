#include "dataflow.hpp"
#include <algorithm>
#include <vector>
#include <iostream>

namespace Analysis {

    DataFlowEngine::DataFlowEngine(const CFG& cfg, const std::vector<VTableInfo>& vtables, uint64_t image_base)
        : cfg_(cfg), image_base_(image_base) {
        for (const auto& vt : vtables) {
            vtable_vas_.push_back(image_base + vt.rva.value);
        }
        std::sort(vtable_vas_.begin(), vtable_vas_.end());
    }

    int DataFlowEngine::map_reg(unsigned int reg) const {
        switch(reg) {
            case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AH: case X86_REG_AL: return 0;
            case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BH: case X86_REG_BL: return 1;
            case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CH: case X86_REG_CL: return 2;
            case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DH: case X86_REG_DL: return 3;
            case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return 4;
            case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return 5;
            case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return 6;
            case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return 7;
            case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B: return 8;
            case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B: return 9;
            case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return 10;
            case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return 11;
            case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return 12;
            case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return 13;
            case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return 14;
            case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return 15;
            default: return -1;
        }
    }

    void DataFlowEngine::run() {
        const auto& blocks = cfg_.get_blocks();
        size_t num_blocks = blocks.size();

        if (num_blocks == 0) return;

        block_in_states_.resize(num_blocks);
        block_out_states_.resize(num_blocks);

        std::vector<uint32_t> worklist;
        worklist.reserve(num_blocks);
        std::vector<bool> in_worklist(num_blocks, true);

        for (size_t i = 0; i < num_blocks; ++i) {
            worklist.push_back(static_cast<uint32_t>(i));
        }

        size_t iterations = 0;
        while (!worklist.empty()) {
            uint32_t curr_id = worklist.back();
            worklist.pop_back();
            in_worklist[curr_id] = false;

            iterations++;
            if (iterations % 10000 == 0) {
                std::cout << "    [DFA] Iteration " << iterations << ", Worklist: " << worklist.size() << "\r" << std::flush;
            }

            const auto& block = *blocks[curr_id];
            RegisterState in_state = meet(block.pred_ids);

            if (in_state == block_in_states_[curr_id] && iterations > num_blocks) {
                continue;
            }

            block_in_states_[curr_id] = in_state;
            RegisterState out_state = transfer(block, in_state);

            if (out_state != block_out_states_[curr_id]) {
                block_out_states_[curr_id] = out_state;
                for (uint32_t succ_id : block.succ_ids) {
                    if (!in_worklist[succ_id]) {
                        worklist.push_back(succ_id);
                        in_worklist[succ_id] = true;
                    }
                }
            }
        }
        std::cout << "\n    [DFA] Converged in " << iterations << " iterations." << std::endl;

        scan_linear_fallback();
    }

    void DataFlowEngine::scan_linear_fallback() {
        std::cout << "    [DFA] Running Linear Sweep Fallback..." << std::endl;
        const auto& blocks = cfg_.get_blocks();

        for (const auto& block : blocks) {
            RegisterState local_state;
            for (const auto& instr : block->instructions) {
                process_instruction(instr, local_state, true);
            }
        }
    }

    RegisterState DataFlowEngine::meet(const std::vector<uint32_t>& pred_ids) {
        if (pred_ids.empty()) return RegisterState();

        RegisterState result = block_out_states_[pred_ids[0]];

        for (size_t i = 1; i < pred_ids.size(); ++i) {
            const auto& p_state = block_out_states_[pred_ids[i]];
            for (int r = 0; r < TRACKED_REG_COUNT; ++r) {
                result.regs[static_cast<size_t>(r)] = Lattice::meet(result.regs[static_cast<size_t>(r)], p_state.regs[static_cast<size_t>(r)]);
            }
        }
        return result;
    }

    RegisterState DataFlowEngine::transfer(const BasicBlock& block, const RegisterState& in_state) {
        RegisterState state = in_state;
        for (const auto& instr : block.instructions) {
            process_instruction(instr, state, false);
        }
        return state;
    }

    void DataFlowEngine::process_instruction(const Instruction& instr, RegisterState& state, bool is_heuristic) {
        if (instr.id == X86_INS_MOV) {
            auto& dest = instr.operands[0];
            auto& src = instr.operands[1];

            if (dest.type == X86_OP_REG) {
                int dst_idx = map_reg(dest.reg);
                if (dst_idx >= 0) {
                    if (dest.size >= 4) {
                        if (src.type == X86_OP_IMM) {
                            state.regs[static_cast<size_t>(dst_idx)] = Constant{static_cast<uint64_t>(src.imm)};
                        } else if (src.type == X86_OP_REG) {
                            int src_idx = map_reg(src.reg);
                            if (src_idx >= 0) {
                                state.regs[static_cast<size_t>(dst_idx)] = state.regs[static_cast<size_t>(src_idx)];
                            } else {
                                state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                            }
                        } else {
                            state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                        }
                    } else {
                        state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                    }
                }
            }
            else if (dest.type == X86_OP_MEM && src.type == X86_OP_REG) {
                int src_idx = map_reg(src.reg);
                if (src_idx >= 0 && std::holds_alternative<Constant>(state.regs[static_cast<size_t>(src_idx)])) {
                    uint64_t val = std::get<Constant>(state.regs[static_cast<size_t>(src_idx)]).value;
                    if (std::binary_search(vtable_vas_.begin(), vtable_vas_.end(), val)) {
                        bool exists = false;
                        for(const auto& a : assignments_) if(a.addr.value == instr.address.value) exists = true;
                        if (!exists) {
                            assignments_.push_back({instr.address, val, instr.mnemonic + " " + instr.op_str, is_heuristic});
                        }
                    }
                }
            }
            else if (dest.type == X86_OP_MEM && src.type == X86_OP_IMM) {
                uint64_t val = static_cast<uint64_t>(src.imm);
                if (std::binary_search(vtable_vas_.begin(), vtable_vas_.end(), val)) {
                     bool exists = false;
                     for(const auto& a : assignments_) if(a.addr.value == instr.address.value) exists = true;
                     if (!exists) assignments_.push_back({instr.address, val, instr.mnemonic + " " + instr.op_str, is_heuristic});
                }
            }
        }
        else if (instr.id == X86_INS_XOR) {
            if (instr.operands[0].type == X86_OP_REG && instr.operands[1].type == X86_OP_REG &&
                instr.operands[0].reg == instr.operands[1].reg) {
                int idx = map_reg(instr.operands[0].reg);
                if (idx >= 0) state.regs[static_cast<size_t>(idx)] = Constant{0};
            } else {
                if (instr.operands[0].type == X86_OP_REG) {
                    int idx = map_reg(instr.operands[0].reg);
                    if (idx >= 0) state.regs[static_cast<size_t>(idx)] = Bottom{};
                }
            }
        }
        else if (instr.id == X86_INS_LEA) {
            auto& dest = instr.operands[0];
            auto& src = instr.operands[1];
            int dst_idx = map_reg(dest.reg);

            if (dst_idx >= 0) {
                if (dest.size >= 4) {
                    if (src.type == X86_OP_MEM && src.mem.base == X86_REG_RIP) {
                        uint64_t rip = image_base_ + instr.address.value + instr.size;
                        uint64_t target = rip + static_cast<uint64_t>(src.mem.disp);
                        state.regs[static_cast<size_t>(dst_idx)] = Constant{target};
                    } else {
                        state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                    }
                } else {
                    state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                }
            }
        }
        else {
            for (int i = 0; i < instr.op_count; ++i) {
                if (instr.operands[i].type == X86_OP_REG && (instr.operands[i].access & CS_AC_WRITE)) {
                    int idx = map_reg(instr.operands[i].reg);
                    if (idx >= 0) state.regs[static_cast<size_t>(idx)] = Bottom{};
                }
            }
        }
    }
}