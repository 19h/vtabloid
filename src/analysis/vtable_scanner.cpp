#include "vtable_scanner.hpp"
#include "rtti.hpp"

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
            if (!sec.is_readable() || sec.is_executable()) continue;

            for (uint32_t off = 0; off <= sec.raw_size - ptr_size; off += static_cast<uint32_t>(ptr_size)) {
                uint64_t ptr_val = 0;
                if (loader_.is_64bit()) {
                    auto val = view.read<uint64_t>(sec.raw_ptr + off);
                    if (val) ptr_val = *val;
                } else {
                    auto val = view.read<uint32_t>(sec.raw_ptr + off);
                    if (val) ptr_val = *val;
                }

                if (!ptr_val) continue;

                if (is_executable_ptr(ptr_val)) {
                    Common::RVA curr_rva = sec.rva + off;

                    bool rtti = false;
                    std::string name = "Unknown";

                    if (curr_rva.value >= ptr_size) {
                        auto col_ptr_off = loader_.rva_to_offset(curr_rva - static_cast<uint32_t>(ptr_size));
                        if (col_ptr_off) {
                            uint64_t col_va = 0;
                            if (loader_.is_64bit()) {
                                auto v = view.read<uint64_t>(*col_ptr_off);
                                if (v) col_va = *v;
                            } else {
                                auto v = view.read<uint32_t>(*col_ptr_off);
                                if (v) col_va = *v;
                            }

                            if (col_va > base) {
                                auto res = validate_rtti(Common::RVA{static_cast<uint32_t>(col_va - base)});
                                if (res) { rtti = true; name = *res; }
                            }
                        }
                    }

                    std::vector<uint32_t> methods;
                    methods.push_back(static_cast<uint32_t>(ptr_val - base));

                    uint32_t lookahead = static_cast<uint32_t>(ptr_size);
                    while (off + lookahead <= sec.raw_size - ptr_size) {
                        uint64_t next_ptr = 0;
                        if (loader_.is_64bit()) {
                            auto v = view.read<uint64_t>(sec.raw_ptr + off + lookahead);
                            if (v) next_ptr = *v;
                        } else {
                            auto v = view.read<uint32_t>(sec.raw_ptr + off + lookahead);
                            if (v) next_ptr = *v;
                        }

                        if (!next_ptr || !is_executable_ptr(next_ptr)) break;
                        methods.push_back(static_cast<uint32_t>(next_ptr - base));
                        lookahead += static_cast<uint32_t>(ptr_size);
                    }

                    if (rtti || methods.size() >= 2) {
                        vtables_.push_back({curr_rva, methods.size(), name, rtti});
                        off += (static_cast<uint32_t>(methods.size()) * static_cast<uint32_t>(ptr_size)) - static_cast<uint32_t>(ptr_size);
                    }
                }
            }
        }
    }
}