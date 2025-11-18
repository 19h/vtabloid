#include "vtable_scanner.hpp"
#include "rtti.hpp"
#include <array>

namespace Analysis {

    VTableScanner::VTableScanner(const PE::PELoader& loader) : loader_(loader) {}

    bool VTableScanner::is_executable_ptr(uint64_t va) const {
        uint64_t base = loader_.view().image_base();
        if (va < base) return false;
        if (va - base > 0xFFFFFFFF) return false;

        Common::RVA rva{static_cast<uint32_t>(va - base)};
        for (const auto& sec : loader_.sections()) {
            if (sec.is_executable() && sec.contains(rva)) return true;
        }
        return false;
    }

    // Heuristic: Check for common x86/x64 function prologues
    bool VTableScanner::check_method_prologue(uint64_t va) const {
        uint64_t base = loader_.view().image_base();
        if (va < base) return false;
        Common::RVA rva{static_cast<uint32_t>(va - base)};

        auto offset = loader_.rva_to_offset(rva);
        if (!offset) return false;

        const uint8_t* p = loader_.view().ptr(*offset);
        if (!p) return false;

        // Ensure we have enough bytes to check (at least 4)
        if (!loader_.view().contains(*offset, 4)) return false;

        // 1. PUSH instructions (Common in prologues)
        // push rbp (0x55)
        if (p[0] == 0x55) return true;
        // push rbx (0x53), push rsi (0x56), push rdi (0x57)
        if (p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57) return true;
        // push r12..r15 (0x41 0x54 .. 0x41 0x57)
        if (p[0] == 0x41 && (p[1] >= 0x54 && p[1] <= 0x57)) return true;

        // 2. Stack Allocation
        // sub rsp, imm8 (0x48 0x83 0xEC)
        if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return true;
        // sub rsp, imm32 (0x48 0x81 0xEC)
        if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return true;

        // 3. Control Flow Thunks
        // ret (0xC3), ret imm16 (0xC2)
        if (p[0] == 0xC3 || p[0] == 0xC2) return true;
        // jmp rel32 (0xE9), jmp rel8 (0xEB)
        if (p[0] == 0xE9 || p[0] == 0xEB) return true;
        // jmp [rip+disp] (0xFF 0x25)
        if (p[0] == 0xFF && p[1] == 0x25) return true;

        // 4. Register Initialization / Argument Homing
        // xor eax, eax (0x31 0xC0 / 0x33 0xC0) - Common for returning 0
        if ((p[0] == 0x31 || p[0] == 0x33) && p[1] == 0xC0) return true;
        // mov [rsp+...], reg (0x48 0x89 ...)
        if (p[0] == 0x48 && p[1] == 0x89 && (p[2] == 0x5C || p[2] == 0x4C)) return true;
        // lea ... (0x48 0x8D) - Often used to load address of string/data
        if (p[0] == 0x48 && p[1] == 0x8D) return true;

        // 5. Intel CET
        // endbr64 (0xF3 0x0F 0x1E 0xFA)
        if (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) return true;

        return false;
    }

    std::optional<std::string> VTableScanner::validate_rtti(Common::RVA col_rva) {
        if (loader_.is_64bit()) {
            return validate_rtti_64(col_rva);
        } else {
            return validate_rtti_32(col_rva);
        }
    }

    std::optional<std::string> VTableScanner::validate_rtti_32(Common::RVA col_rva) {
        auto offset = loader_.rva_to_offset(col_rva);
        if (!offset) return std::nullopt;

        auto col = loader_.view().read<MSVC::RTTICompleteObjectLocator32>(*offset);
        if (!col || col->signature != 0) return std::nullopt;

        uint64_t base = loader_.view().image_base();
        if (col->pTypeDescriptor < base) return std::nullopt;

        auto td_offset = loader_.rva_to_offset(Common::RVA{col->pTypeDescriptor - static_cast<uint32_t>(base)});
        if (!td_offset) return std::nullopt;

        return loader_.view().read_string(*td_offset + 8);
    }

    std::optional<std::string> VTableScanner::validate_rtti_64(Common::RVA col_rva) {
        auto offset = loader_.rva_to_offset(col_rva);
        if (!offset) return std::nullopt;

        auto col = loader_.view().read<MSVC::RTTICompleteObjectLocator64>(*offset);
        if (!col || col->signature != 1) return std::nullopt;

        if (static_cast<uint32_t>(col->pSelf) != col_rva.value) return std::nullopt;

        auto td_offset = loader_.rva_to_offset(Common::RVA{static_cast<uint32_t>(col->pTypeDescriptor)});
        if (!td_offset) return std::nullopt;

        return loader_.view().read_string(*td_offset + 16);
    }

    void VTableScanner::scan() {
        const auto& view = loader_.view();
        uint64_t base = view.image_base();
        size_t ptr_size = loader_.is_64bit() ? 8 : 4;

        for (const auto& sec : loader_.sections()) {
            if (!sec.is_readable() || sec.is_executable() || sec.is_writable()) continue;

            for (uint32_t off = 0; off <= sec.raw_size - ptr_size; off += static_cast<uint32_t>(ptr_size)) {
                auto ptr_val = view.read_ptr(sec.raw_ptr + off, loader_.architecture());
                if (!ptr_val || *ptr_val == 0) continue;

                if (is_executable_ptr(*ptr_val)) {
                    Common::RVA curr_rva = sec.rva + off;

                    bool rtti = false;
                    std::string name = "Unknown";

                    if (curr_rva.value >= ptr_size) {
                        auto col_ptr_off = loader_.rva_to_offset(curr_rva - static_cast<uint32_t>(ptr_size));
                        if (col_ptr_off) {
                            auto col_va = view.read_ptr(*col_ptr_off, loader_.architecture());
                            if (col_va && *col_va > base) {
                                auto res = validate_rtti(Common::RVA{static_cast<uint32_t>(*col_va - base)});
                                if (res) { rtti = true; name = *res; }
                            }
                        }
                    }

                    std::vector<uint32_t> methods;
                    methods.push_back(static_cast<uint32_t>(*ptr_val - base));

                    // Check prologue of the first method
                    bool valid_prologue = check_method_prologue(*ptr_val);

                    uint32_t lookahead = static_cast<uint32_t>(ptr_size);
                    while (off + lookahead <= sec.raw_size - ptr_size) {
                        auto next_ptr = view.read_ptr(sec.raw_ptr + off + lookahead, loader_.architecture());
                        if (!next_ptr || !is_executable_ptr(*next_ptr)) break;

                        methods.push_back(static_cast<uint32_t>(*next_ptr - base));
                        lookahead += static_cast<uint32_t>(ptr_size);
                    }

                    // Heuristic Refinement:
                    // 1. Must have RTTI OR
                    // 2. Must have >= 2 methods AND valid prologue on the first method
                    // 3. OR must have >= 5 methods (Relaxed check for large vtables without standard prologues)
                    if (rtti || (methods.size() >= 2 && valid_prologue) || methods.size() >= 5) {
                        vtables_.push_back({curr_rva, methods.size(), name, rtti, methods, valid_prologue});
                        off += (static_cast<uint32_t>(methods.size()) * static_cast<uint32_t>(ptr_size)) - static_cast<uint32_t>(ptr_size);
                    }
                }
            }
        }
    }
}