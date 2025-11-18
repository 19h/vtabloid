#include "dataflow.hpp"
#include <algorithm>
#include <vector>
#include <iostream>

namespace Analysis {

    DataFlowEngine::DataFlowEngine(const CFG& cfg, const Common::BinaryLoader& loader, const std::vector<VTableInfo>& vtables)
        : cfg_(cfg), loader_(loader), image_base_(loader.view().image_base()) {
        for (const auto& vt : vtables) {
            vtable_vas_.push_back(image_base_ + vt.rva.value);
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
        }
        if (reg >= X86_REG_XMM0 && reg <= X86_REG_XMM15) {
            return 16 + static_cast<int>(reg - X86_REG_XMM0);
        }
        return -1;
    }

    void DataFlowEngine::seed_this_alias(RegisterState& st) const {
        int rdi = map_reg(X86_REG_RDI);
        int rcx = map_reg(X86_REG_RCX);
        if (rdi >= 0) st.this_like[static_cast<size_t>(rdi)] = 1; // SysV AMD64
        if (rcx >= 0) st.this_like[static_cast<size_t>(rcx)] = 1; // MSVC x64
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
            seed_this_alias(local_state);
            for (const auto& instr : block->instructions) {
                process_instruction(instr, local_state, true);
            }
        }
    }

    RegisterState DataFlowEngine::meet(const std::vector<uint32_t>& pred_ids) {
        if (pred_ids.empty()) {
            RegisterState seeded;
            seed_this_alias(seeded); // seed at function entries (no predecessors)
            return seeded;
        }

        RegisterState result = block_out_states_[pred_ids[0]];

        for (size_t i = 1; i < pred_ids.size(); ++i) {
            const auto& p_state = block_out_states_[pred_ids[i]];
            for (int r = 0; r < TRACKED_REG_COUNT; ++r) {
                result.regs[static_cast<size_t>(r)] =
                    Lattice::meet(result.regs[static_cast<size_t>(r)], p_state.regs[static_cast<size_t>(r)]);
                // OR for alias bits
                result.this_like[static_cast<size_t>(r)] =
                    static_cast<uint8_t>(result.this_like[static_cast<size_t>(r)] | p_state.this_like[static_cast<size_t>(r)]);
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
        auto clear_alias = [&](int idx) {
            if (idx >= 0) state.this_like[static_cast<size_t>(idx)] = 0;
        };

        // CALL: Invalidate volatile registers (RAX, RCX, RDX, R8..R11, XMM0-5) and alias marks
        if (instr.is_call()) {
            int volatiles[] = {0, 2, 3, 8, 9, 10, 11};
            for (int idx : volatiles) {
                state.regs[static_cast<size_t>(idx)] = Bottom{};
                clear_alias(idx);
            }
            for (int i = 0; i < 6; ++i) state.regs[16 + static_cast<size_t>(i)] = Bottom{};
            return;
        }

        bool is_mov = (instr.id == X86_INS_MOV || instr.id == X86_INS_MOVAPS ||
                       instr.id == X86_INS_MOVUPS || instr.id == X86_INS_MOVDQA ||
                       instr.id == X86_INS_MOVDQU || instr.id == X86_INS_MOVQ);

        if (is_mov) {
            auto& dest = instr.operands[0];
            auto& src  = instr.operands[1];

            if (dest.type == X86_OP_REG) {
                int dst_idx = map_reg(dest.reg);
                if (dst_idx >= 0) {
                    if (src.type == X86_OP_IMM) {
                        state.regs[static_cast<size_t>(dst_idx)] = Constant{static_cast<uint64_t>(src.imm)};
                        clear_alias(dst_idx);
                    } else if (src.type == X86_OP_REG) {
                        int src_idx = map_reg(src.reg);
                        if (src_idx >= 0) {
                            state.regs[static_cast<size_t>(dst_idx)] = state.regs[static_cast<size_t>(src_idx)];
                            // Propagate 'this' alias across register moves
                            state.this_like[static_cast<size_t>(dst_idx)] = state.this_like[static_cast<size_t>(src_idx)];
                        } else {
                            state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                            clear_alias(dst_idx);
                        }
                    } else if (src.type == X86_OP_MEM) {
                        uint64_t target_addr = 0;
                        bool resolved = false;

                        if (src.mem.base == X86_REG_RIP) {
                            target_addr = image_base_ + instr.address.value + instr.size + static_cast<uint64_t>(src.mem.disp);
                            resolved = true;
                        } else if (src.mem.base == X86_REG_INVALID) {
                            target_addr = static_cast<uint64_t>(src.mem.disp);
                            resolved = true;
                        } else {
                            // Handle one level of indirection via constant pointer register (GOT load via LEA; then MOV reg, [reg])
                            int base_idx = map_reg(src.mem.base);
                            if (base_idx >= 0 &&
                                std::holds_alternative<Constant>(state.regs[static_cast<size_t>(base_idx)]) &&
                                src.mem.index == X86_REG_INVALID) {
                                target_addr = std::get<Constant>(state.regs[static_cast<size_t>(base_idx)]).value +
                                              static_cast<uint64_t>(src.mem.disp);
                                resolved = true;
                            }
                        }

                        if (resolved) {
                            Common::RVA rva{0};
                            if (target_addr >= image_base_) {
                                rva = Common::RVA{static_cast<uint32_t>(target_addr - image_base_)};
                            } else {
                                if (image_base_ == 0) rva = Common::RVA{static_cast<uint32_t>(target_addr)};
                            }

                            auto ptr_val = loader_.read_ptr_at(rva);
                            if (ptr_val) {
                                state.regs[static_cast<size_t>(dst_idx)] = Constant{*ptr_val};
                            } else {
                                state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                            }
                        } else {
                            state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                        }
                        clear_alias(dst_idx);
                    } else {
                        state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                        clear_alias(dst_idx);
                    }
                }
            }
            else if (dest.type == X86_OP_MEM) {
                // Ignore stores to stack to avoid false positives.
                if (dest.mem.base == X86_REG_RSP || dest.mem.base == X86_REG_RBP ||
                    dest.mem.base == X86_REG_ESP || dest.mem.base == X86_REG_EBP) {
                    return;
                }

                // Require destination to alias 'this' (RDI/RCX or propagated alias).
                bool dest_is_object = false;
                int base_idx = map_reg(dest.mem.base);
                if (base_idx >= 0 && state.this_like[static_cast<size_t>(base_idx)]) {
                    dest_is_object = true;
                } else if (dest.mem.base == X86_REG_RDI || dest.mem.base == X86_REG_EDI ||
                           dest.mem.base == X86_REG_RCX || dest.mem.base == X86_REG_ECX) {
                    dest_is_object = true;
                }

                if (!dest_is_object) return;

                uint64_t val = 0;
                bool has_val = false;

                if (src.type == X86_OP_REG) {
                    int src_idx = map_reg(src.reg);
                    if (src_idx >= 0 && std::holds_alternative<Constant>(state.regs[static_cast<size_t>(src_idx)])) {
                        val = std::get<Constant>(state.regs[static_cast<size_t>(src_idx)]).value;
                        has_val = true;
                    }
                } else if (src.type == X86_OP_IMM) {
                    val = static_cast<uint64_t>(src.imm);
                    has_val = true;
                }

                if (has_val) {
                    // Fuzzy match for VTable address (Itanium ABI allows +16)
                    auto it = std::upper_bound(vtable_vas_.begin(), vtable_vas_.end(), val);
                    bool match = false;

                    if (it != vtable_vas_.begin()) {
                        uint64_t candidate = *std::prev(it);
                        if (val >= candidate && val <= candidate + 16) {
                            val = candidate; // normalize to vtable start
                            match = true;
                        }
                    }

                    if (match) {
                        bool exists = false;
                        for (const auto& a : assignments_) if (a.addr.value == instr.address.value) { exists = true; break; }
                        if (!exists) {
                            assignments_.push_back({instr.address, val, instr.mnemonic + std::string(" ") + instr.op_str, is_heuristic});
                        }
                    }
                }
            }
        }
        else if (instr.id == X86_INS_XOR) {
            if (instr.operands[0].type == X86_OP_REG && instr.operands[1].type == X86_OP_REG &&
                instr.operands[0].reg == instr.operands[1].reg) {
                int idx = map_reg(instr.operands[0].reg);
                if (idx >= 0) {
                    state.regs[static_cast<size_t>(idx)] = Constant{0};
                    state.this_like[static_cast<size_t>(idx)] = 0;
                }
            } else {
                if (instr.operands[0].type == X86_OP_REG) {
                    int idx = map_reg(instr.operands[0].reg);
                    if (idx >= 0) {
                        state.regs[static_cast<size_t>(idx)] = Bottom{};
                        state.this_like[static_cast<size_t>(idx)] = 0;
                    }
                }
            }
        }
        else if (instr.id == X86_INS_LEA) {
            auto& dest = instr.operands[0];
            auto& src  = instr.operands[1];
            int dst_idx = map_reg(dest.reg);

            if (dst_idx >= 0) {
                if (src.type == X86_OP_MEM) {
                    uint64_t target = 0;
                    bool resolved = false;

                    if (src.mem.base == X86_REG_RIP) {
                        uint64_t rip = image_base_ + instr.address.value + instr.size;
                        target = rip + static_cast<uint64_t>(src.mem.disp);
                        resolved = true;
                    } else if (src.mem.base == X86_REG_INVALID) {
                        target = static_cast<uint64_t>(src.mem.disp);
                        resolved = true;
                    } else {
                        int base_idx2 = map_reg(src.mem.base);
                        if (base_idx2 >= 0 &&
                            std::holds_alternative<Constant>(state.regs[static_cast<size_t>(base_idx2)]) &&
                            src.mem.index == X86_REG_INVALID) {
                            target = std::get<Constant>(state.regs[static_cast<size_t>(base_idx2)]).value +
                                     static_cast<uint64_t>(src.mem.disp);
                            resolved = true;
                        }
                    }

                    if (resolved) {
                        state.regs[static_cast<size_t>(dst_idx)] = Constant{target};
                        // If LEA is based on 'this', keep alias bit, else clear.
                        int base_idx2 = map_reg(src.mem.base);
                        if (base_idx2 >= 0 && state.this_like[static_cast<size_t>(base_idx2)] && src.mem.index == X86_REG_INVALID) {
                            state.this_like[static_cast<size_t>(dst_idx)] = 1;
                        } else {
                            state.this_like[static_cast<size_t>(dst_idx)] = 0;
                        }
                    } else {
                        state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                        state.this_like[static_cast<size_t>(dst_idx)] = 0;
                    }
                } else {
                    state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                    state.this_like[static_cast<size_t>(dst_idx)] = 0;
                }
            }
        }
        else if (instr.id == X86_INS_ADD || instr.id == X86_INS_SUB) {
            const auto& dest = instr.operands[0];
            const auto& src  = instr.operands[1];

            if (dest.type == X86_OP_REG && src.type == X86_OP_IMM) {
                if (dest.reg == X86_REG_RSP) {
                    // ignore stack pointer arithmetic for DFA purposes
                } else {
                    int dst_idx = map_reg(dest.reg);
                    if (dst_idx >= 0) {
                        if (std::holds_alternative<Constant>(state.regs[static_cast<size_t>(dst_idx)])) {
                            auto c = std::get<Constant>(state.regs[static_cast<size_t>(dst_idx)]).value;
                            uint64_t updated = (instr.id == X86_INS_ADD)
                                ? (c + static_cast<uint64_t>(src.imm))
                                : (c - static_cast<uint64_t>(src.imm));
                            state.regs[static_cast<size_t>(dst_idx)] = Constant{updated};
                        } else if (std::holds_alternative<SymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)])) {
                            auto& sym = std::get<SymbolicPtr>(state.regs[static_cast<size_t>(dst_idx)]);
                            if (instr.id == X86_INS_ADD) sym.offset += src.imm;
                            else sym.offset -= src.imm;
                            state.regs[static_cast<size_t>(dst_idx)] = sym;
                        } else {
                            state.regs[static_cast<size_t>(dst_idx)] = Bottom{};
                        }
                    }
                }
            } else {
                for (int i = 0; i < instr.op_count; ++i) {
                    if (instr.operands[i].type == X86_OP_REG && (instr.operands[i].access & CS_AC_WRITE)) {
                        int idx = map_reg(instr.operands[i].reg);
                        if (idx >= 0) {
                            state.regs[static_cast<size_t>(idx)] = Bottom{};
                            state.this_like[static_cast<size_t>(idx)] = 0;
                        }
                    }
                }
            }
        }
        else {
            // Conservative invalidation
            for (int i = 0; i < instr.op_count; ++i) {
                if (instr.operands[i].type == X86_OP_REG && (instr.operands[i].access & CS_AC_WRITE)) {
                    int idx = map_reg(instr.operands[i].reg);
                    if (idx >= 0) {
                        state.regs[static_cast<size_t>(idx)] = Bottom{};
                        state.this_like[static_cast<size_t>(idx)] = 0;
                    }
                }
            }
        }
    }
}
