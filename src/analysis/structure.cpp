#include "structure.hpp"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <iterator>

namespace Analysis {

    StructState::StructState() : rsp_delta(0) {
        for(auto& r : regs) r = Top{};
    }

    bool StructState::operator==(const StructState& other) const {
        if (rsp_delta != other.rsp_delta) return false;
        if (regs != other.regs) return false;
        if (stack.size() != other.stack.size()) return false;
        return std::equal(stack.begin(), stack.end(), other.stack.begin());
    }

    bool StructState::operator!=(const StructState& other) const {
        return !(*this == other);
    }

    StructureAnalyzer::StructureAnalyzer(const CFG& cfg, const PE::PELoader& loader)
        : cfg_(cfg), loader_(loader) {
        const auto& blocks = cfg_.get_blocks();
        for (const auto& blk : blocks) {
            rva_to_block_id_[blk->start_address.value] = blk->id;
        }
    }

    int StructureAnalyzer::map_reg(unsigned int reg) const {
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

    Common::RVA StructureAnalyzer::find_function_start(Common::RVA instr_addr) const {
        const auto& funcs = cfg_.functions();
        auto it = std::upper_bound(funcs.begin(), funcs.end(), instr_addr,
            [](Common::RVA val, const Common::RVA& func_start) {
                return val.value < func_start.value;
            });

        if (it != funcs.begin()) {
            return *std::prev(it);
        }
        return Common::RVA{0};
    }

    void StructureAnalyzer::record_access(uint64_t vtable_va, int64_t offset, uint32_t size, bool is_write, Common::RVA addr, const std::string& ctx) {
        layouts_[vtable_va].vtable_va = vtable_va;
        layouts_[vtable_va].fields.push_back({offset, size, is_write, addr, ctx});
    }

    void StructureAnalyzer::analyze_vtables(const std::vector<VTableInfo>& vtables) {
        uint64_t image_base = loader_.view().image_base();
        for (const auto& vt : vtables) {
            uint64_t vt_va = image_base + vt.rva.value;
            for (uint32_t method_rva : vt.methods) {
                if (method_rva == 0 || method_rva > 0x10000000) continue;
                if (processed_functions_.count(method_rva)) continue;

                analyze_function(Common::RVA{method_rva}, vt_va);
                processed_functions_.insert(method_rva);
            }
        }
    }

    void StructureAnalyzer::analyze_constructors(const std::vector<Assignment>& assignments) {
        for (const auto& assign : assignments) {
            Common::RVA func_start = find_function_start(assign.addr);
            if (func_start.value == 0) continue;

            // We re-analyze the entire function containing the assignment.
            // This ensures we catch all field initializations, even those before the vtable assignment
            // (though standard ABI usually does vtable first, optimization can reorder).
            // We pass the vtable VA as context so all 'this' accesses are attributed to it.
            analyze_function(func_start, assign.vtable_va);
        }
    }

    void StructureAnalyzer::analyze_function(Common::RVA start_rva, uint64_t vtable_context) {
        auto it = rva_to_block_id_.find(start_rva.value);
        if (it == rva_to_block_id_.end()) return;

        uint32_t start_idx = it->second;
        size_t num_blocks = cfg_.get_blocks().size();

        std::vector<StructState> block_in(num_blocks);
        std::vector<StructState> block_out(num_blocks);
        std::vector<bool> in_worklist(num_blocks, false);
        std::vector<uint32_t> worklist;

        worklist.push_back(start_idx);
        in_worklist[start_idx] = true;

        // Initialize Entry State
        // RCX (x64) or ECX (x86) is 'this'
        int this_reg = loader_.is_64bit() ? map_reg(X86_REG_RCX) : map_reg(X86_REG_ECX);
        if (this_reg >= 0) {
            block_in[start_idx].regs[static_cast<size_t>(this_reg)] = ComplexSymbolicPtr{0, ComplexSymbolicPtr::BaseType::This};
        }

        // Initialize Stack Pointer (RSP) as Stack Base
        // RSP Delta is 0 at entry.
        // We treat [RSP+0] as the return address (conceptually), args are above.
        // Locals are below.
        // We don't need to set a register value for RSP, the state tracks rsp_delta implicitly.

        while (!worklist.empty()) {
            uint32_t curr = worklist.back();
            worklist.pop_back();
            in_worklist[curr] = false;

            const auto& block = *cfg_.get_blocks()[curr];

            StructState in_state;
            if (curr == start_idx) {
                in_state = block_in[curr];
            } else {
                in_state = meet(block.pred_ids, block_out);
            }
            block_in[curr] = in_state;

            StructState out_state = transfer(block, in_state, vtable_context);

            if (out_state != block_out[curr]) {
                block_out[curr] = out_state;
                for (uint32_t succ : block.succ_ids) {
                    if (!in_worklist[succ]) {
                        worklist.push_back(succ);
                        in_worklist[succ] = true;
                    }
                }
            }
        }
    }

    StructValue StructureAnalyzer::meet_value(const StructValue& a, const StructValue& b) {
        if (std::holds_alternative<Top>(a)) return b;
        if (std::holds_alternative<Top>(b)) return a;
        if (std::holds_alternative<Bottom>(a) || std::holds_alternative<Bottom>(b)) return Bottom{};

        if (std::holds_alternative<Constant>(a) && std::holds_alternative<Constant>(b)) {
            if (std::get<Constant>(a).value == std::get<Constant>(b).value) return a;
        }

        if (std::holds_alternative<ComplexSymbolicPtr>(a) && std::holds_alternative<ComplexSymbolicPtr>(b)) {
            const auto& sa = std::get<ComplexSymbolicPtr>(a);
            const auto& sb = std::get<ComplexSymbolicPtr>(b);
            if (sa.base_type == sb.base_type && sa.offset == sb.offset) return a;
        }

        return Bottom{};
    }

    StructState StructureAnalyzer::meet(const std::vector<uint32_t>& pred_ids, const std::vector<StructState>& block_out_states) {
        if (pred_ids.empty()) return StructState();

        StructState result = block_out_states[pred_ids[0]];

        for (size_t i = 1; i < pred_ids.size(); ++i) {
            const auto& p_state = block_out_states[pred_ids[i]];

            // If RSP deltas mismatch, stack state is undefined/unreliable
            if (result.rsp_delta != p_state.rsp_delta) {
                // In a rigorous analysis, this is a control flow merge with unbalanced stack.
                // We invalidate stack knowledge but keep registers (if possible).
                // For simplicity, we just clear stack knowledge.
                result.stack.clear();
                // We can't easily reconcile RSP delta, so we pick one (unsafe) or stop tracking stack.
                // We'll assume the first predecessor's delta for future ops, but clear the map.
            } else {
                // Meet Stack Slots
                auto it = result.stack.begin();
                while (it != result.stack.end()) {
                    if (p_state.stack.count(it->first)) {
                        it->second = meet_value(it->second, p_state.stack.at(it->first));
                        if (std::holds_alternative<Bottom>(it->second)) {
                            it = result.stack.erase(it);
                        } else {
                            ++it;
                        }
                    } else {
                        it = result.stack.erase(it);
                    }
                }
            }

            // Meet Registers
            for (int r = 0; r < TRACKED_REG_COUNT; ++r) {
                result.regs[static_cast<size_t>(r)] = meet_value(result.regs[static_cast<size_t>(r)], p_state.regs[static_cast<size_t>(r)]);
            }
        }
        return result;
    }

    StructState StructureAnalyzer::transfer(const BasicBlock& block, const StructState& in_state, uint64_t vtable_context) {
        StructState state = in_state;

        for (const auto& instr : block.instructions) {
            // 1. Memory Access Analysis (Field Discovery)
            for (int i = 0; i < instr.op_count; ++i) {
                const auto& op = instr.operands[i];
                if (op.type == X86_OP_MEM) {
                    int base_idx = map_reg(op.mem.base);

                    // Check Register Base
                    if (base_idx >= 0 && std::holds_alternative<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                        auto sym = std::get<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);

                        if (sym.base_type == ComplexSymbolicPtr::BaseType::This) {
                            int64_t final_offset = sym.offset + op.mem.disp;
                            bool is_write = (op.access & CS_AC_WRITE);

                            uint32_t size = 0;
                            // Infer size from other operand if register
                            for(int j=0; j<instr.op_count; ++j) {
                                if (instr.operands[j].type == X86_OP_REG) {
                                    if (instr.operands[j].reg >= X86_REG_RAX && instr.operands[j].reg <= X86_REG_R15) size = 8;
                                    else if (instr.operands[j].reg >= X86_REG_EAX && instr.operands[j].reg <= X86_REG_R15D) size = 4;
                                    else if (instr.operands[j].reg >= X86_REG_AX && instr.operands[j].reg <= X86_REG_R15W) size = 2;
                                    else size = 1;
                                    break;
                                }
                            }

                            std::string ctx = instr.mnemonic + std::string(" ") + instr.op_str;
                            record_access(vtable_context, final_offset, size, is_write, instr.address, ctx);
                        }
                    }
                }
            }

            // 2. Symbolic Propagation & Stack Tracking
            if (instr.id == X86_INS_MOV) {
                auto& dest = instr.operands[0];
                auto& src = instr.operands[1];

                if (dest.type == X86_OP_REG) {
                    int dst_idx = map_reg(dest.reg);
                    if (dst_idx >= 0) {
                        if (src.type == X86_OP_REG) {
                            int src_idx = map_reg(src.reg);
                            if (src_idx >= 0) state.regs[static_cast<size_t>(dst_idx)] = state.regs[static_cast<size_t>(src_idx)];
                        } else if (src.type == X86_OP_MEM) {
                            // Load from Stack?
                            // Check if base is RSP
                            if (src.mem.base == X86_REG_RSP) {
                                int64_t slot = state.rsp_delta + src.mem.disp;
                                if (state.stack.count(slot)) {
                                    state.regs[static_cast<size_t>(dst_idx)] = state.stack.at(slot);
                                } else {
                                    state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                                }
                            } else {
                                // Check if base is a pointer to stack (e.g. RBP)
                                int base_idx = map_reg(src.mem.base);
                                if (base_idx >= 0 && std::holds_alternative<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                                    auto sym = std::get<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);
                                    if (sym.base_type == ComplexSymbolicPtr::BaseType::Stack) {
                                        int64_t slot = sym.offset + src.mem.disp;
                                        if (state.stack.count(slot)) {
                                            state.regs[static_cast<size_t>(dst_idx)] = state.stack.at(slot);
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
                        } else if (src.type == X86_OP_IMM) {
                            state.regs[static_cast<size_t>(dst_idx)] = Constant{static_cast<uint64_t>(src.imm)};
                        }
                    }
                } else if (dest.type == X86_OP_MEM) {
                    // Store to Stack?
                    int64_t target_slot = -1;
                    bool is_stack_store = false;

                    if (dest.mem.base == X86_REG_RSP) {
                        target_slot = state.rsp_delta + dest.mem.disp;
                        is_stack_store = true;
                    } else {
                        int base_idx = map_reg(dest.mem.base);
                        if (base_idx >= 0 && std::holds_alternative<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                            auto sym = std::get<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);
                            if (sym.base_type == ComplexSymbolicPtr::BaseType::Stack) {
                                target_slot = sym.offset + dest.mem.disp;
                                is_stack_store = true;
                            }
                        }
                    }

                    if (is_stack_store) {
                        if (src.type == X86_OP_REG) {
                            int src_idx = map_reg(src.reg);
                            if (src_idx >= 0) state.stack[target_slot] = state.regs[static_cast<size_t>(src_idx)];
                        } else if (src.type == X86_OP_IMM) {
                            state.stack[target_slot] = Constant{static_cast<uint64_t>(src.imm)};
                        }
                    }
                }
            }
            else if (instr.id == X86_INS_LEA) {
                auto& dest = instr.operands[0];
                auto& src = instr.operands[1];
                int dst_idx = map_reg(dest.reg);
                if (dst_idx >= 0) {
                    if (src.type == X86_OP_MEM) {
                        // LEA Dest, [RSP + Disp] -> Dest = StackPtr(rsp_delta + disp)
                        if (src.mem.base == X86_REG_RSP) {
                            state.regs[static_cast<size_t>(dst_idx)] = ComplexSymbolicPtr{state.rsp_delta + src.mem.disp, ComplexSymbolicPtr::BaseType::Stack};
                        } else {
                            int base_idx = map_reg(src.mem.base);
                            if (base_idx >= 0 && std::holds_alternative<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                                auto sym = std::get<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);
                                state.regs[static_cast<size_t>(dst_idx)] = ComplexSymbolicPtr{sym.offset + src.mem.disp, sym.base_type};
                            } else {
                                state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                            }
                        }
                    }
                }
            }
            else if (instr.id == X86_INS_ADD) {
                auto& dest = instr.operands[0];
                auto& src = instr.operands[1];
                if (dest.type == X86_OP_REG && dest.reg == X86_REG_RSP && src.type == X86_OP_IMM) {
                    state.rsp_delta += src.imm;
                } else if (dest.type == X86_OP_REG && src.type == X86_OP_IMM) {
                    int dst_idx = map_reg(dest.reg);
                    if (dst_idx >= 0 && std::holds_alternative<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)])) {
                        auto& sym = std::get<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)]);
                        sym.offset += src.imm;
                    }
                }
            }
            else if (instr.id == X86_INS_SUB) {
                auto& dest = instr.operands[0];
                auto& src = instr.operands[1];
                if (dest.type == X86_OP_REG && dest.reg == X86_REG_RSP && src.type == X86_OP_IMM) {
                    state.rsp_delta -= src.imm;
                } else if (dest.type == X86_OP_REG && src.type == X86_OP_IMM) {
                    int dst_idx = map_reg(dest.reg);
                    if (dst_idx >= 0 && std::holds_alternative<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)])) {
                        auto& sym = std::get<ComplexSymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)]);
                        sym.offset -= src.imm;
                    }
                }
            }
            else if (instr.id == X86_INS_PUSH) {
                auto& src = instr.operands[0];
                state.rsp_delta -= 8;
                if (src.type == X86_OP_REG) {
                    int src_idx = map_reg(src.reg);
                    if (src_idx >= 0) state.stack[state.rsp_delta] = state.regs[static_cast<size_t>(src_idx)];
                } else if (src.type == X86_OP_IMM) {
                    state.stack[state.rsp_delta] = Constant{static_cast<uint64_t>(src.imm)};
                }
            }
            else if (instr.id == X86_INS_POP) {
                auto& dest = instr.operands[0];
                if (dest.type == X86_OP_REG) {
                    int dst_idx = map_reg(dest.reg);
                    if (dst_idx >= 0) {
                        if (state.stack.count(state.rsp_delta)) {
                            state.regs[static_cast<size_t>(dst_idx)] = state.stack.at(state.rsp_delta);
                        } else {
                            state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                        }
                    }
                }
                state.rsp_delta += 8;
            }
        }
        return state;
    }
}
