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

    StructureAnalyzer::StructureAnalyzer(const CFG& cfg, const Common::BinaryLoader& loader)
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
            case X86_REG_R8:  case X86_REG_R8D:  case X86_REG_R8W:  case X86_REG_R8B:  return 8;
            case X86_REG_R9:  case X86_REG_R9D:  case X86_REG_R9W:  case X86_REG_R9B:  return 9;
            case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return 10;
            case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return 11;
            case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return 12;
            case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return 13;
            case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return 14;
            case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return 15;
        }
        if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM15) {
            return 16 + static_cast<int>(reg - X86_REG_XMM0);
        }
        if (reg >= X86_REG_YMM0 && reg <= X86_REG_YMM15) {
            return 16 + static_cast<int>(reg - X86_REG_YMM0);
        }
        return -1;
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

    void StructureAnalyzer::record_access(uint64_t vtable_va, int64_t offset, uint32_t size, bool is_write,
                                        Common::RVA addr, const std::string& ctx, bool is_array, bool is_vector) {
        FieldAccess access;
        access.offset = offset;
        access.size = size;
        access.is_write = is_write;
        access.instruction_addr = addr;
        access.context = ctx;
        access.is_array_access = is_array;
        access.is_vector_op = is_vector;

        layouts_[vtable_va].vtable_va = vtable_va;
        layouts_[vtable_va].fields.push_back(access);
    }

    void StructureAnalyzer::analyze_vtables(const std::vector<VTableInfo>& vtables) {
        uint64_t image_base = loader_.view().image_base();
        for (const auto& vt : vtables) {
            uint64_t vt_va = image_base + vt.rva.value;
            for (uint32_t method_rva : vt.methods) {
                if (method_rva == 0 || method_rva > 0x10000000) continue;
                if (processed_functions_.count(method_rva)) continue;

                Context ctx;
                ctx.vtable_va = vt_va;
                ctx.is_constructor = false;

                analyze_function(Common::RVA{method_rva}, ctx);
                processed_functions_.insert(method_rva);
            }
        }
    }

    void StructureAnalyzer::analyze_constructors(const std::vector<Assignment>& assignments) {
        std::map<uint32_t, std::set<uint64_t>> func_to_vtables;

        for (const auto& assign : assignments) {
            Common::RVA func_start = find_function_start(assign.addr);
            if (func_start.value != 0) {
                func_to_vtables[func_start.value].insert(assign.vtable_va);
            }
        }

        std::cout << "    [Structure] Analyzing " << func_to_vtables.size() << " constructor contexts..." << std::endl;

        for (const auto& [func_rva_val, vtables] : func_to_vtables) {
            for (uint64_t vt_va : vtables) {
                Context ctx;
                ctx.vtable_va = vt_va;
                ctx.is_constructor = true;
                analyze_function(Common::RVA{func_rva_val}, ctx);
            }
        }
    }

    void StructureAnalyzer::analyze_function(Common::RVA start_rva, Context ctx) {
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

        int this_reg = loader_.is_64bit() ? map_reg(X86_REG_RCX) : map_reg(X86_REG_ECX);
        if (this_reg >= 0) {
            block_in[start_idx].regs[static_cast<size_t>(this_reg)] = SymbolicPtr{SymbolicPtr::Base::This, 0, ctx.vtable_va};
        }

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

            StructState out_state = transfer(block, in_state, ctx);

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

    StructState StructureAnalyzer::meet(const std::vector<uint32_t>& pred_ids, const std::vector<StructState>& block_out_states) {
        if (pred_ids.empty()) return StructState();

        StructState result = block_out_states[pred_ids[0]];

        for (size_t i = 1; i < pred_ids.size(); ++i) {
            const auto& p_state = block_out_states[pred_ids[i]];

            if (result.rsp_delta != p_state.rsp_delta) {
                result.stack.clear();
            } else {
                auto it = result.stack.begin();
                while (it != result.stack.end()) {
                    if (p_state.stack.count(it->first)) {
                        it->second = Lattice::meet(it->second, p_state.stack.at(it->first));
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

            for (int r = 0; r < TOTAL_REG_COUNT; ++r) {
                result.regs[static_cast<size_t>(r)] = Lattice::meet(result.regs[static_cast<size_t>(r)], p_state.regs[static_cast<size_t>(r)]);
            }
        }
        return result;
    }

    void StructureAnalyzer::handle_mov(const Instruction& instr, StructState& state, const Context& ctx) {
        const auto& dest = instr.operands[0];
        const auto& src = instr.operands[1];

        auto check_access = [&](const cs_x86_op& op, bool is_write) {
            if (op.type != X86_OP_MEM) return;

            int base_idx = map_reg(op.mem.base);
            int index_idx = map_reg(op.mem.index);

            if (base_idx >= 0 && std::holds_alternative<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                auto sym = std::get<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);

                if (sym.type == SymbolicPtr::Base::This) {
                    int64_t final_offset = sym.offset + op.mem.disp;
                    bool is_array = (index_idx >= 0);

                    uint32_t size = 0;
                    const auto& other_op = is_write ? src : dest;
                    if (other_op.type == X86_OP_REG) {
                        if (other_op.reg >= X86_REG_XMM0) size = 16;
                        else if (other_op.reg >= X86_REG_RAX && other_op.reg <= X86_REG_R15) size = 8;
                        else if (other_op.reg >= X86_REG_EAX && other_op.reg <= X86_REG_R15D) size = 4;
                        else if (other_op.reg >= X86_REG_AX && other_op.reg <= X86_REG_R15W) size = 2;
                        else size = 1;
                    } else if (other_op.type == X86_OP_IMM) {
                        size = 4;
                    }

                    bool is_vector = (size >= 16);
                    std::string disasm = instr.mnemonic + std::string(" ") + instr.op_str;

                    record_access(ctx.vtable_va, final_offset, size, is_write, instr.address, disasm, is_array, is_vector);
                }
            }
        };

        check_access(dest, true);
        check_access(src, false);

        if (dest.type == X86_OP_REG) {
            int dst_idx = map_reg(dest.reg);
            if (dst_idx < 0) return;

            if (src.type == X86_OP_REG) {
                int src_idx = map_reg(src.reg);
                if (src_idx >= 0) state.regs[static_cast<size_t>(dst_idx)] = state.regs[static_cast<size_t>(src_idx)];
                else state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
            }
            else if (src.type == X86_OP_IMM) {
                state.regs[static_cast<size_t>(dst_idx)] = Constant{static_cast<uint64_t>(src.imm)};
            }
            else if (src.type == X86_OP_MEM) {
                if (src.mem.base == X86_REG_RSP) {
                    int64_t slot = state.rsp_delta + src.mem.disp;
                    if (state.stack.count(slot)) {
                        state.regs[static_cast<size_t>(dst_idx)] = state.stack.at(slot);
                    } else {
                        state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                    }
                } else {
                    int base_idx = map_reg(src.mem.base);
                    if (base_idx >= 0 && std::holds_alternative<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                        auto sym = std::get<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);
                        if (sym.type == SymbolicPtr::Base::Stack) {
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
            }
        }
        else if (dest.type == X86_OP_MEM) {
            int64_t target_slot = 0;
            bool is_stack = false;

            if (dest.mem.base == X86_REG_RSP) {
                target_slot = state.rsp_delta + dest.mem.disp;
                is_stack = true;
            } else {
                int base_idx = map_reg(dest.mem.base);
                if (base_idx >= 0 && std::holds_alternative<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                    auto sym = std::get<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);
                    if (sym.type == SymbolicPtr::Base::Stack) {
                        target_slot = sym.offset + dest.mem.disp;
                        is_stack = true;
                    }
                }
            }

            if (is_stack) {
                if (src.type == X86_OP_REG) {
                    int src_idx = map_reg(src.reg);
                    if (src_idx >= 0) state.stack[target_slot] = state.regs[static_cast<size_t>(src_idx)];
                } else if (src.type == X86_OP_IMM) {
                    state.stack[target_slot] = Constant{static_cast<uint64_t>(src.imm)};
                }
            }
        }
    }

    void StructureAnalyzer::handle_lea(const Instruction& instr, StructState& state) {
        const auto& dest = instr.operands[0];
        const auto& src = instr.operands[1];
        int dst_idx = map_reg(dest.reg);
        if (dst_idx < 0) return;

        if (src.type == X86_OP_MEM) {
            if (src.mem.base == X86_REG_RIP) {
                uint64_t rip = loader_.view().image_base() + instr.address.value + instr.size;
                uint64_t target = rip + static_cast<uint64_t>(src.mem.disp);
                state.regs[static_cast<size_t>(dst_idx)] = Constant{target};
                return;
            }

            if (src.mem.base == X86_REG_RSP) {
                state.regs[static_cast<size_t>(dst_idx)] = SymbolicPtr{SymbolicPtr::Base::Stack, state.rsp_delta + src.mem.disp, 0};
                return;
            }

            int base_idx = map_reg(src.mem.base);
            if (base_idx >= 0 && std::holds_alternative<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)])) {
                auto sym = std::get<SymbolicPtr>(state.regs[static_cast<size_t>(base_idx)]);
                sym.offset += src.mem.disp;
                state.regs[static_cast<size_t>(dst_idx)] = sym;
                return;
            }
        }
        state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
    }

    void StructureAnalyzer::handle_arithmetic(const Instruction& instr, StructState& state) {
        const auto& dest = instr.operands[0];
        const auto& src = instr.operands[1];

        if (dest.type == X86_OP_REG && src.type == X86_OP_IMM) {
            if (dest.reg == X86_REG_RSP) {
                if (instr.id == X86_INS_ADD) state.rsp_delta += src.imm;
                else if (instr.id == X86_INS_SUB) state.rsp_delta -= src.imm;
                return;
            }

            int dst_idx = map_reg(dest.reg);
            if (dst_idx >= 0 && std::holds_alternative<SymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)])) {
                auto& sym = std::get<SymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)]);
                if (instr.id == X86_INS_ADD) sym.offset += src.imm;
                else if (instr.id == X86_INS_SUB) sym.offset -= src.imm;
            }
        }
    }

    void StructureAnalyzer::handle_stack_op(const Instruction& instr, StructState& state) {
        if (instr.id == X86_INS_PUSH) {
            const auto& src = instr.operands[0];
            state.rsp_delta -= 8;
            if (src.type == X86_OP_REG) {
                int src_idx = map_reg(src.reg);
                if (src_idx >= 0) state.stack[state.rsp_delta] = state.regs[static_cast<size_t>(src_idx)];
            }
        } else if (instr.id == X86_INS_POP) {
            const auto& dest = instr.operands[0];
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

    void StructureAnalyzer::handle_logic(const Instruction& instr, StructState& state) {
        if (instr.id == X86_INS_XOR) {
            const auto& op0 = instr.operands[0];
            const auto& op1 = instr.operands[1];
            if (op0.type == X86_OP_REG && op1.type == X86_OP_REG && op0.reg == op1.reg) {
                int idx = map_reg(op0.reg);
                if (idx >= 0) state.regs[static_cast<size_t>(idx)] = Constant{0};
            }
        }
    }

    StructState StructureAnalyzer::transfer(const BasicBlock& block, const StructState& in_state, const Context& ctx) {
        StructState state = in_state;

        for (const auto& instr : block.instructions) {
            switch (instr.id) {
                case X86_INS_MOV:
                case X86_INS_MOVAPS:
                case X86_INS_MOVUPS:
                case X86_INS_MOVDQU:
                case X86_INS_MOVZX:
                case X86_INS_MOVSX:
                    handle_mov(instr, state, ctx);
                    break;
                case X86_INS_LEA:
                    handle_lea(instr, state);
                    break;
                case X86_INS_ADD:
                case X86_INS_SUB:
                    handle_arithmetic(instr, state);
                    break;
                case X86_INS_PUSH:
                case X86_INS_POP:
                    handle_stack_op(instr, state);
                    break;
                case X86_INS_XOR:
                    handle_logic(instr, state);
                    break;
                default:
                    for (int i = 0; i < instr.op_count; ++i) {
                        if (instr.operands[i].type == X86_OP_REG && (instr.operands[i].access & CS_AC_WRITE)) {
                            int idx = map_reg(instr.operands[i].reg);
                            if (idx >= 0) state.regs[static_cast<size_t>(idx)] = Bottom{};
                        }
                    }
                    break;
            }
        }
        return state;
    }
}
