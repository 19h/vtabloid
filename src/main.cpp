#include <iostream>
#include <iomanip>
#include <map>
#include <algorithm>
#include "pe/pe_loader.hpp"
#include "analysis/vtable_scanner.hpp"
#include "analysis/cfg.hpp"
#include "analysis/dataflow.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pe_binary>" << std::endl;
        return 1;
    }

    std::cout << "[*] Loading PE Binary..." << std::endl;
    PE::PELoader loader(argv[1]);
    if (!loader.load()) {
        std::cerr << "[!] Failed to load binary." << std::endl;
        return 1;
    }
    std::cout << "    ImageBase: 0x" << std::hex << loader.view().image_base() << std::endl;
    std::cout << "    Architecture: " << (loader.is_64bit() ? "x64" : "x86") << std::endl;

    std::cout << "[*] Scanning for VTables..." << std::endl;
    Analysis::VTableScanner scanner(loader);
    scanner.scan();
    const auto& vtables = scanner.results();
    std::cout << "    Found " << std::dec << vtables.size() << " candidates." << std::endl;

    std::cout << "[*] Building Control Flow Graph..." << std::endl;
    Analysis::CFG cfg(loader);
    cfg.build();
    std::cout << "    Discovered " << cfg.get_blocks().size() << " basic blocks." << std::endl;

    std::cout << "[*] Running Iterative Data Flow Analysis..." << std::endl;
    Analysis::DataFlowEngine engine(cfg, vtables, loader.view().image_base());
    engine.run();

    // --- Visualization Logic ---

    // 1. Map VTable VA to Info for symbol lookup
    std::map<uint64_t, const Analysis::VTableInfo*> vtable_lookup;
    uint64_t image_base = loader.view().image_base();
    for (const auto& vt : vtables) {
        vtable_lookup[image_base + vt.rva.value] = &vt;
    }

    // 2. Group assignments by VTable VA
    std::map<uint64_t, std::vector<Analysis::Assignment>> grouped_assignments;
    for (const auto& assign : engine.assignments()) {
        grouped_assignments[assign.vtable_va].push_back(assign);
    }

    std::cout << "\n=== VTable Analysis Report ===" << std::endl;

    for (auto& [va, assigns] : grouped_assignments) {
        std::string name = "Unknown";
        bool has_rtti = false;
        size_t method_count = 0;

        if (vtable_lookup.count(va)) {
            const auto* info = vtable_lookup[va];
            name = info->symbol_name;
            has_rtti = info->has_rtti;
            method_count = info->method_count;
        }

        std::cout << "\n[+] VTable: 0x" << std::hex << va
                  << " | Methods: " << std::dec << method_count
                  << " | RTTI: " << (has_rtti ? "YES" : "NO")
                  << " | Symbol: " << name << std::endl;

        // Sort assignments by instruction address
        std::sort(assigns.begin(), assigns.end(),
            [](const Analysis::Assignment& a, const Analysis::Assignment& b) {
                return a.addr.value < b.addr.value;
            });

        for (const auto& ref : assigns) {
            std::cout << "    - 0x" << std::hex << ref.addr.value
                      << ": " << ref.desc
                      << (ref.is_heuristic ? " [Heuristic]" : "") << std::endl;
        }
    }

    return 0;
}