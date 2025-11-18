#include "cfg.hpp"
#include <queue>
#include <iostream>
#include <algorithm>

namespace Analysis {

    CFG::CFG(const PE::PELoader& loader) : loader_(loader) {
        cs_mode mode = loader.is_64bit() ? CS_MODE_64 : CS_MODE_32;
        cs_open(CS_ARCH_X86, mode, &cs_handle_);
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
            disassemble_function(func);
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

        const auto& view = loader_.view();
        for (const auto& sec : loader_.sections()) {
            if (!sec.is_executable()) continue;

            const uint8_t* data = view.ptr(sec.raw_ptr);
            if (!data) continue;

            if (loader_.is_64bit()) {
                for (size_t i = 0; i < sec.raw_size - 4; ++i) {
                    if (data[i] == 0x48 && data[i+1] == 0x83 && data[i+2] == 0xEC) {
                        function_entries_.push_back(sec.rva + static_cast<uint32_t>(i));
                    }
                    else if (data[i] == 0x48 && data[i+1] == 0x89 && data[i+2] == 0x5C && data[i+3] == 0x24) {
                        function_entries_.push_back(sec.rva + static_cast<uint32_t>(i));
                    }
                }
            } else {
                for (size_t i = 0; i < sec.raw_size - 3; ++i) {
                    if (data[i] == 0x55 && data[i+1] == 0x8B && data[i+2] == 0xEC) {
                        function_entries_.push_back(sec.rva + static_cast<uint32_t>(i));
                    }
                }
            }
        }

        std::sort(function_entries_.begin(), function_entries_.end(),
            [](const Common::RVA& a, const Common::RVA& b) { return a.value < b.value; });
        function_entries_.erase(std::unique(function_entries_.begin(), function_entries_.end()), function_entries_.end());
    }

    void CFG::disassemble_function(Common::RVA start) {
        std::queue<Common::RVA> worklist;
        worklist.push(start);

        while (!worklist.empty()) {
            Common::RVA curr = worklist.front();
            worklist.pop();

            if (rva_to_block_.count(curr.value)) continue;

            auto block = std::make_shared<BasicBlock>();
            block->start_address = curr;

            Common::RVA pc = curr;
            bool end_of_block = false;

            while (!end_of_block) {
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

                if (cs_insn_group(cs_handle_, &insn[0], CS_GRP_JUMP) ||
                    cs_insn_group(cs_handle_, &insn[0], CS_GRP_RET)) {

                    end_of_block = true;

                    if (instr.id == X86_INS_JMP || instr.id == X86_INS_JNE || instr.id == X86_INS_JE) {
                        if (instr.operands[0].type == X86_OP_IMM) {
                            uint64_t target_va = static_cast<uint64_t>(instr.operands[0].imm);
                            uint64_t base = loader_.view().image_base();
                            if (target_va >= base) {
                                Common::RVA target{static_cast<uint32_t>(target_va - base)};
                                worklist.push(target);
                            }
                        }
                    }

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

    void CFG::linearize_graph() {
        linear_blocks_.reserve(rva_to_block_.size());
        uint32_t index = 0;

        for (auto& [addr, block] : rva_to_block_) {
            block->id = index++;
            linear_blocks_.push_back(block);
        }

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
                    uint64_t target_va = static_cast<uint64_t>(last.operands[0].imm);
                    uint64_t base = loader_.view().image_base();
                    if (target_va >= base) {
                        add_edge(Common::RVA{static_cast<uint32_t>(target_va - base)});
                    }
                }
            } else if (last.id >= X86_INS_JAE && last.id <= X86_INS_JS) {
                 if (last.operands[0].type == X86_OP_IMM) {
                    uint64_t target_va = static_cast<uint64_t>(last.operands[0].imm);
                    uint64_t base = loader_.view().image_base();
                    if (target_va >= base) {
                        add_edge(Common::RVA{static_cast<uint32_t>(target_va - base)});
                    }
                }
                add_edge(block->end_address);
            } else {
                add_edge(block->end_address);
            }
        }
    }
}