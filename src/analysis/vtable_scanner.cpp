#include "vtable_scanner.hpp"
#include "rtti.hpp"
#include <array>

namespace Analysis {

    VTableScanner::VTableScanner(const Common::BinaryLoader& loader) : loader_(loader) {}

    bool VTableScanner::is_executable_ptr(uint64_t va) const {
        uint64_t base = loader_.view().image_base();

        Common::RVA rva{0};
        if (va >= base) {
             rva = Common::RVA{static_cast<uint32_t>(va - base)};
        } else {
             if (base == 0) rva = Common::RVA{static_cast<uint32_t>(va)};
             else return false;
        }

        for (const auto& sec : loader_.sections()) {
            if (sec.is_executable && sec.contains(rva)) return true;
        }
        return false;
    }

    bool VTableScanner::check_method_prologue(uint64_t va) const {
        uint64_t base = loader_.view().image_base();
        Common::RVA rva{0};

        if (va >= base) {
             rva = Common::RVA{static_cast<uint32_t>(va - base)};
        } else {
             if (base == 0) rva = Common::RVA{static_cast<uint32_t>(va)};
             else return false;
        }

        auto offset = loader_.rva_to_offset(rva);
        if (!offset) return false;

        const uint8_t* p = loader_.view().ptr(*offset);
        if (!p) return false;

        if (!loader_.view().contains(*offset, 4)) return false;

        if (p[0] == 0x55) return true;
        if (p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57) return true;
        if (p[0] == 0x41 && (p[1] >= 0x54 && p[1] <= 0x57)) return true;

        if (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) return true;
        if (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) return true;

        if (p[0] == 0xC3 || p[0] == 0xC2) return true;
        if (p[0] == 0xE9 || p[0] == 0xEB) return true;
        if (p[0] == 0xFF && p[1] == 0x25) return true;

        if ((p[0] == 0x31 || p[0] == 0x33) && p[1] == 0xC0) return true;
        if (p[0] == 0x48 && p[1] == 0x89 && (p[2] == 0x5C || p[2] == 0x4C)) return true;
        if (p[0] == 0x48 && p[1] == 0x8D) return true;

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
        uint64_t base = loader_.view().image_base();
        size_t ptr_size = loader_.is_64bit() ? 8 : 4;

        for (const auto& sec : loader_.sections()) {
            // Include .data.rel.ro (readable & non-executable); allow writable to catch relocated vtables.
            if (!sec.is_readable || sec.is_executable) continue;

            for (uint32_t rva_off = 0; rva_off <= sec.virtual_size - ptr_size; rva_off += static_cast<uint32_t>(ptr_size)) {
                Common::RVA curr_rva = sec.rva + rva_off;

                auto ptr_val = loader_.read_ptr_at(curr_rva);
                if (!ptr_val || *ptr_val == 0) continue;

                if (is_executable_ptr(*ptr_val)) {
                    bool rtti = false;
                    std::string name = "Unknown";

                    if (curr_rva.value >= ptr_size) {
                        auto col_ptr_rva = curr_rva - static_cast<uint32_t>(ptr_size);
                        auto col_va = loader_.read_ptr_at(col_ptr_rva);

                        if (col_va && *col_va > base) {
                            auto res = validate_rtti(Common::RVA{static_cast<uint32_t>(*col_va - base)});
                            if (res) { rtti = true; name = *res; }
                        }
                    }

                    std::vector<uint32_t> methods;
                    uint64_t method_va = *ptr_val;
                    uint32_t method_rva = (base == 0) ? static_cast<uint32_t>(method_va) : static_cast<uint32_t>(method_va - base);
                    methods.push_back(method_rva);

                    bool valid_prologue = check_method_prologue(method_va);

                    uint32_t lookahead = static_cast<uint32_t>(ptr_size);
                    while (rva_off + lookahead <= sec.virtual_size - ptr_size) {
                        auto next_ptr = loader_.read_ptr_at(curr_rva + lookahead);
                        if (!next_ptr || !is_executable_ptr(*next_ptr)) break;

                        uint64_t next_va = *next_ptr;
                        uint32_t next_rva = (base == 0) ? static_cast<uint32_t>(next_va) : static_cast<uint32_t>(next_va - base);
                        methods.push_back(next_rva);

                        lookahead += static_cast<uint32_t>(ptr_size);
                    }

                    if (rtti || (methods.size() >= 2 && valid_prologue) || methods.size() >= 5) {
                        vtables_.push_back({curr_rva, methods.size(), name, rtti, methods, valid_prologue});
                        rva_off += (static_cast<uint32_t>(methods.size()) * static_cast<uint32_t>(ptr_size)) - static_cast<uint32_t>(ptr_size);
                    }
                }
            }
        }
    }
}
