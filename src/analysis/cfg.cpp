#include "cfg.hpp"
#include <queue>
#include <iostream>
#include <algorithm>
#include <stdexcept>

namespace Analysis {

    CFG::CFG(const PE::PELoader& loader) : loader_(loader) {
        cs_mode mode = loader.is_64bit() ? CS_MODE_64 : CS_MODE_32;
        if (cs_open(CS_ARCH_X86, mode, &cs_handle_) != CS_ERR_OK) {
            throw std::runtime_error("Failed to initialize Capstone");
        }
        cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);
        cs_option(cs_handle_, CS_OPT_SKIPDATA, CS_OPT_ON);
    }

    CFG::~CFG() {
        cs_close(&cs_handle_);
    }

    void CFG::build() {
        discover_functions();
        std::cout << "    [CFG] Discovered " << function_entries_.size() << " function entry points." << std::endl;

        size_t processed = 0;
        for (auto func : function_entries_) {
            disassemble_recursive(func);
            processed++;
            if (processed % 1000 == 0) {
                std::cout << "    [CFG] Processed " << processed << " functions..." << "\r" << std::flush;
            }
        }
        std::cout << std::endl;

        linearize_graph();
        std::cout << "    [CFG] Linearized " << linear_blocks_.size() << " basic blocks." << std::endl;
    }

    void CFG::discover_functions() {
        function_entries_.push_back(loader_.entry_point());

        // 1. Exception Directory (x64)
        if (loader_.is_64bit()) {
            auto [pdata_rva, pdata_size] = loader_.exception_directory();
            if (pdata_rva.value != 0 && pdata_size > 0) {
                auto pdata_offset = loader_.rva_to_offset(pdata_rva);
                if (pdata_offset) {
                    size_t count = pdata_size / sizeof(PE::IMAGE_RUNTIME_FUNCTION_ENTRY);
                    const auto* entries = reinterpret_cast<const PE::IMAGE_RUNTIME_FUNCTION_ENTRY*>(
                        loader_.view().ptr(*pdata_offset)
                    );

                    if (entries) {
                        for (size_t i = 0; i < count; ++i) {
                            function_entries_.push_back(Common::RVA{entries[i].BeginAddress});
                        }
                    }
                }
            }
        }

        // 2. Prolog Scanning (Heuristic)
        const auto& view = loader_.view();
        for (const auto& sec : loader_.sections()) {
            if (!sec.is_executable()) continue;

            const uint8_t* data = view.ptr(sec.raw_ptr);
            if (!data) continue;

            if (loader_.is_64bit()) {
                for (size_t i = 0; i < sec.raw_size - 4; ++i) {
                    // sub rsp, imm8/32
                    if (data[i] == 0x48 && data[i+1] == 0x83 && data[i+2] == 0xEC) {
                        function_entries_.push_back(sec.rva + static_cast<uint32_t>(i));
                    }
                    // mov [rsp+...], reg (common prolog)
                    else if (data[i] == 0x48 && data[i+1] == 0x89 && data[i+2] == 0x5C && data[i+3] == 0x24) {
                        function_entries_.push_back(sec.rva + static_cast<uint32_t>(i));
                    }
                }
            } else {
                for (size_t i = 0; i < sec.raw_size - 3; ++i) {
                    // push ebp; mov ebp, esp
                    if (data[i] == 0x55 && data[i+1] == 0x8B && data[i+2] == 0xEC) {
                        function_entries_.push_back(sec.rva + static_cast<uint32_t>(i));
                    }
                }
            }
        }

        std::sort(function_entries_.begin(), function_entries_.end());
        function_entries_.erase(std::unique(function_entries_.begin(), function_entries_.end()), function_entries_.end());
    }

    void CFG::disassemble_recursive(Common::RVA start) {
        std::queue<Common::RVA> worklist;
        worklist.push(start);

        while (!worklist.empty()) {
            Common::RVA curr = worklist.front();
            worklist.pop();

            if (visited_instructions_.count(curr.value)) continue;
            if (rva_to_block_.count(curr.value)) continue;

            auto block = std::make_shared<BasicBlock>();
            block->start_address = curr;

            Common::RVA pc = curr;
            bool end_of_block = false;

            while (!end_of_block) {
                visited_instructions_.insert(pc.value);
                auto offset = loader_.rva_to_offset(pc);
                if (!offset) break;

                const uint8_t* code = loader_.view().ptr(*offset);
                cs_insn* insn;
                size_t count = cs_disasm(cs_handle_, code, 15, loader_.view().image_base() + pc.value, 1, &insn);

                if (count == 0) break;

                Instruction instr;
                instr.address = pc;
                instr.size = insn[0].size;
                instr.mnemonic = insn[0].mnemonic;
                instr.op_str = insn[0].op_str;
                instr.id = insn[0].id;

                instr.op_count = std::min<uint8_t>(insn[0].detail->x86.op_count, 8);
                for(int i=0; i<instr.op_count; ++i) instr.operands[i] = insn[0].detail->x86.operands[i];

                block->instructions.push_back(instr);
                pc = pc + instr.size;

                // Control Flow Handling
                if (cs_insn_group(cs_handle_, &insn[0], CS_GRP_JUMP) ||
                    cs_insn_group(cs_handle_, &insn[0], CS_GRP_RET)) {

                    end_of_block = true;

                    // Direct Jumps
                    // Use X86_INS_JS as the upper bound for conditional jumps in Capstone enum
                    if (instr.id == X86_INS_JMP || (instr.id >= X86_INS_JAE && instr.id <= X86_INS_JS)) {
                        if (instr.operands[0].type == X86_OP_IMM) {
                            uint64_t target_va = static_cast<uint64_t>(instr.operands[0].imm);
                            uint64_t base = loader_.view().image_base();
                            if (target_va >= base) {
                                Common::RVA target{static_cast<uint32_t>(target_va - base)};
                                worklist.push(target);
                            }
                        } else if (instr.id == X86_INS_JMP && instr.operands[0].type == X86_OP_MEM) {
                            // Indirect Jump - Potential Switch Table
                            handle_jump_table(instr, instr.address);

                            // Add discovered targets to worklist
                            if (indirect_jumps_.count(instr.address.value)) {
                                for (const auto& target : indirect_jumps_[instr.address.value]) {
                                    worklist.push(target);
                                }
                            }
                        }
                    }

                    // Fallthrough for conditional jumps
                    if (instr.id != X86_INS_JMP && instr.id != X86_INS_RET) {
                        worklist.push(pc);
                    }
                }

                cs_free(insn, count);
            }

            block->end_address = pc;
            rva_to_block_[block->start_address.value] = block;
        }
    }

    void CFG::handle_jump_table(const Instruction& instr, Common::RVA current_pc) {
        // Robust Jump Table Recovery
        // Pattern: JMP [Base + Index * Scale + Disp]
        // We attempt to resolve the Base address and iterate until we hit invalid data.

        const auto& op = instr.operands[0];
        if (op.type != X86_OP_MEM) return;

        uint64_t table_base = 0;
        uint64_t image_base = loader_.view().image_base();

        // 1. Resolve Table Base Address
        if (op.mem.base == X86_REG_RIP) {
             // RIP-relative addressing (x64)
             // Explicit cast to uint64_t to suppress -Wsign-conversion
             table_base = image_base + current_pc.value + instr.size + static_cast<uint64_t>(op.mem.disp);
        } else if (op.mem.base == X86_REG_INVALID && op.mem.disp != 0) {
             // Absolute addressing (x86/x64 absolute)
             table_base = static_cast<uint64_t>(op.mem.disp);
        } else {
            // Complex addressing (e.g., register base) requires dataflow analysis to resolve.
            // We skip this in the CFG construction phase to avoid circular dependencies.
            return;
        }

        if (table_base < image_base) return;
        Common::RVA table_rva{static_cast<uint32_t>(table_base - image_base)};

        std::vector<Common::RVA> targets;
        int max_entries = 256; // Safety limit for heuristic scan
        size_t ptr_size = loader_.is_64bit() ? 8 : 4;

        for (int i = 0; i < max_entries; ++i) {
            auto ptr_val = loader_.read_ptr_at(table_rva);
            if (!ptr_val) break;

            // Validate Target
            // 1. Must be within image boundaries
            if (*ptr_val < image_base) break;

            Common::RVA target_rva{static_cast<uint32_t>(*ptr_val - image_base)};

            // 2. Must point to an executable section
            bool valid_target = false;
            for(const auto& sec : loader_.sections()) {
                if (sec.is_executable() && sec.contains(target_rva)) {
                    valid_target = true;
                    break;
                }
            }

            if (!valid_target) break;

            targets.push_back(target_rva);
            table_rva = table_rva + static_cast<uint32_t>(ptr_size);
        }

        if (!targets.empty()) {
            indirect_jumps_[instr.address.value] = targets;
        }
    }

    void CFG::linearize_graph() {
        linear_blocks_.reserve(rva_to_block_.size());
        uint32_t index = 0;

        // Assign IDs
        for (auto& [addr, block] : rva_to_block_) {
            block->id = index++;
            linear_blocks_.push_back(block);
        }

        // Link Edges
        for (auto& block : linear_blocks_) {
            if (block->instructions.empty()) continue;
            const auto& last = block->instructions.back();

            auto add_edge = [&](Common::RVA target) {
                if (rva_to_block_.count(target.value)) {
                    uint32_t target_id = rva_to_block_[target.value]->id;
                    block->succ_ids.push_back(target_id);
                    linear_blocks_[target_id]->pred_ids.push_back(block->id);
                }
            };

            if (last.id == X86_INS_RET) continue;

            if (last.id == X86_INS_JMP) {
                if (last.operands[0].type == X86_OP_IMM) {
                    // Direct Unconditional Jump
                    uint64_t target_va = static_cast<uint64_t>(last.operands[0].imm);
                    uint64_t base = loader_.view().image_base();
                    if (target_va >= base) {
                        add_edge(Common::RVA{static_cast<uint32_t>(target_va - base)});
                    }
                } else if (last.operands[0].type == X86_OP_MEM) {
                    // Indirect Jump (Switch Table)
                    // Retrieve pre-calculated targets from discovery phase
                    if (indirect_jumps_.count(last.address.value)) {
                        for (const auto& target : indirect_jumps_[last.address.value]) {
                            add_edge(target);
                        }
                    }
                }
            } else if (last.id >= X86_INS_JAE && last.id <= X86_INS_JS) {
                // Conditional Jump
                 if (last.operands[0].type == X86_OP_IMM) {
                    uint64_t target_va = static_cast<uint64_t>(last.operands[0].imm);
                    uint64_t base = loader_.view().image_base();
                    if (target_va >= base) {
                        add_edge(Common::RVA{static_cast<uint32_t>(target_va - base)});
                    }
                }
                add_edge(block->end_address); // Fallthrough edge
            } else {
                add_edge(block->end_address); // Fallthrough edge
            }
        }
    }
}