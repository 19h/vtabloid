#pragma once
#include <vector>
#include <string>
#include <optional>
#include "../pe/pe_loader.hpp"

namespace Analysis {

    struct VTableInfo {
        Common::RVA rva;
        size_t method_count;
        std::string symbol_name;
        bool has_rtti;
        std::vector<uint32_t> methods; // RVAs of methods
    };

    class VTableScanner {
    public:
        explicit VTableScanner(const PE::PELoader& loader);
        void scan();
        const std::vector<VTableInfo>& results() const { return vtables_; }

    private:
        bool is_executable_ptr(uint64_t va) const;
        std::optional<std::string> validate_rtti(Common::RVA col_rva);
        std::optional<std::string> validate_rtti_32(Common::RVA col_rva);
        std::optional<std::string> validate_rtti_64(Common::RVA col_rva);

        const PE::PELoader& loader_;
        std::vector<VTableInfo> vtables_;
    };
}