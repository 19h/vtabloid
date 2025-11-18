#include <iostream>
#include <iomanip>
#include <map>
#include <algorithm>
#include "pe/pe_loader.hpp"
#include "analysis/vtable_scanner.hpp"
#include "analysis/cfg.hpp"
#include "analysis/dataflow.hpp"
#include "analysis/structure.hpp"

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

    std::cout << "[*] Running Structure Inference Engine..." << std::endl;
    Analysis::StructureAnalyzer struct_analyzer(cfg, loader);
    struct_analyzer.analyze_vtables(vtables);
    // struct_analyzer.analyze_constructors(engine.assignments()); // Optional expansion

    // --- Visualization Logic ---

    std::map<uint64_t, const Analysis::VTableInfo*> vtable_lookup;
    uint64_t image_base = loader.view().image_base();
    for (const auto& vt : vtables) {
        vtable_lookup[image_base + vt.rva.value] = &vt;
    }

    std::map<uint64_t, std::vector<Analysis::Assignment>> grouped_assignments;
    for (const auto& assign : engine.assignments()) {
        grouped_assignments[assign.vtable_va].push_back(assign);
    }

    const auto& layouts = struct_analyzer.get_layouts();

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

        // Print Reconstructed Layout
        if (layouts.count(va)) {
            const auto& layout = layouts.at(va);
            if (!layout.fields.empty()) {
                std::cout << "    [Layout Inference]" << std::endl;
                // Deduplicate fields by offset
                std::map<int64_t, std::vector<Analysis::FieldAccess>> fields_by_offset;
                for(const auto& f : layout.fields) fields_by_offset[f.offset].push_back(f);

                for(const auto& [offset, accesses] : fields_by_offset) {
                    // Determine likely type based on size
                    uint32_t size = 0;
                    for(const auto& acc : accesses) if(acc.size > size) size = acc.size;

                    std::string type_guess = "unknown";
                    if (size == 1) type_guess = "byte/bool";
                    else if (size == 2) type_guess = "short";
                    else if (size == 4) type_guess = "int/float";
                    else if (size == 8) type_guess = "ptr/qword";

                    std::cout << "      Offset 0x" << std::hex << offset
                              << ": Size " << std::dec << size
                              << " (" << type_guess << ") - "
                              << accesses.size() << " refs" << std::endl;
                }
            }
        }

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
