#pragma once
#include <vector>
#include <string>
#include <optional>
#include "../common/loader.hpp"

namespace Analysis {

    struct VTableInfo {
        Common::RVA rva;
        size_t method_count;
        std::string symbol_name;
        bool has_rtti;
        std::vector<uint32_t> methods; // RVAs of methods
        bool valid_prologues;
    };

    class VTableScanner {
    public:
        explicit VTableScanner(const Common::BinaryLoader& loader);
        void scan();
        const std::vector<VTableInfo>& results() const { return vtables_; }

    private:
        bool is_executable_ptr(uint64_t va) const;
        bool check_method_prologue(uint64_t va) const;
        std::optional<std::string> validate_rtti(Common::RVA col_rva);
        std::optional<std::string> validate_rtti_32(Common::RVA col_rva);
        std::optional<std::string> validate_rtti_64(Common::RVA col_rva);

        const Common::BinaryLoader& loader_;
        std::vector<VTableInfo> vtables_;
    };
}
