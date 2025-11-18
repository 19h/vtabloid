#include <iostream>
#include <iomanip>
#include <map>
#include <algorithm>
#include <fstream>
#include <memory>
#include "pe/pe_loader.hpp"
#include "elf/elf_loader.hpp"
#include "analysis/vtable_scanner.hpp"
#include "analysis/cfg.hpp"
#include "analysis/dataflow.hpp"
#include "analysis/structure.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>" << std::endl;
        return 1;
    }

    std::string filepath = argv[1];
    std::unique_ptr<Common::BinaryLoader> loader;

    // Detect File Type
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        std::cerr << "[!] Failed to open file." << std::endl;
        return 1;
    }

    char magic[4] = {0};
    file.read(magic, 4);
    file.close();

    if (magic[0] == 'M' && magic[1] == 'Z') {
        std::cout << "[*] Detected PE Binary." << std::endl;
        loader = std::make_unique<PE::PELoader>(filepath);
    } else if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        std::cout << "[*] Detected ELF Binary." << std::endl;
        loader = std::make_unique<ELF::ELFLoader>(filepath);
    } else {
        std::cerr << "[!] Unknown file format." << std::endl;
        return 1;
    }

    if (!loader->load()) {
        std::cerr << "[!] Failed to load binary." << std::endl;
        return 1;
    }

    std::cout << "    ImageBase: 0x" << std::hex << loader->view().image_base() << std::endl;
    std::cout << "    Architecture: " << (loader->is_64bit() ? "x64" : "x86") << std::endl;

    std::cout << "[*] Scanning for VTables..." << std::endl;
    Analysis::VTableScanner scanner(*loader);
    scanner.scan();
    const auto& vtables = scanner.results();
    std::cout << "    Found " << std::dec << vtables.size() << " candidates." << std::endl;

    std::cout << "[*] Building Control Flow Graph..." << std::endl;
    Analysis::CFG cfg(*loader);
    cfg.build();
    std::cout << "    Discovered " << cfg.get_blocks().size() << " basic blocks." << std::endl;

    std::cout << "[*] Running Iterative Data Flow Analysis..." << std::endl;
    Analysis::DataFlowEngine engine(cfg, vtables, loader->view().image_base());
    engine.run();

    std::cout << "[*] Running Structure Inference Engine..." << std::endl;
    Analysis::StructureAnalyzer struct_analyzer(cfg, *loader);
    struct_analyzer.analyze_vtables(vtables);
    struct_analyzer.analyze_constructors(engine.assignments());

    // --- Visualization & Filtering Logic ---

    std::map<uint64_t, const Analysis::VTableInfo*> vtable_lookup;
    uint64_t image_base = loader->view().image_base();
    for (const auto& vt : vtables) {
        vtable_lookup[image_base + vt.rva.value] = &vt;
    }

    std::map<uint64_t, std::vector<Analysis::Assignment>> grouped_assignments;
    for (const auto& assign : engine.assignments()) {
        grouped_assignments[assign.vtable_va].push_back(assign);
    }

    const auto& layouts = struct_analyzer.get_layouts();

    std::cout << "\n=== VTable Analysis Report ===" << std::endl;

    int displayed_count = 0;
    int filtered_count = 0;

    for (const auto& vt : vtables) {
        uint64_t va = image_base + vt.rva.value;
        const auto& assigns = grouped_assignments[va];

        // --- SCORING SYSTEM ---
        int score = 0;

        if (vt.has_rtti) score += 50;
        if (!assigns.empty()) score += 20;
        if (assigns.size() > 2) score += 10;
        if (vt.method_count > 2) score += 5;
        if (vt.method_count > 10) score += 5;
        if (vt.valid_prologues) score += 10;

        // --- FILTERING THRESHOLD ---
        if (!vt.has_rtti && assigns.empty()) {
            if (vt.method_count < 5) {
                filtered_count++;
                continue;
            }
        }

        displayed_count++;
        std::cout << "\n[+] VTable: 0x" << std::hex << va
                  << " | Methods: " << std::dec << vt.method_count
                  << " | RTTI: " << (vt.has_rtti ? "YES" : "NO")
                  << " | Symbol: " << vt.symbol_name
                  << " | Score: " << std::dec << score << std::endl;

        if (layouts.count(va)) {
            const auto& layout = layouts.at(va);
            if (!layout.fields.empty()) {
                std::cout << "    [Layout Inference]" << std::endl;
                std::map<int64_t, std::vector<Analysis::FieldAccess>> fields_by_offset;
                for(const auto& f : layout.fields) fields_by_offset[f.offset].push_back(f);

                for(const auto& [offset, accesses] : fields_by_offset) {
                    uint32_t size = 0;
                    for(const auto& acc : accesses) if(acc.size > size) size = acc.size;

                    std::string type_guess = "unknown";
                    if (size == 1) type_guess = "byte/bool";
                    else if (size == 2) type_guess = "short";
                    else if (size == 4) type_guess = "int/float";
                    else if (size == 8) type_guess = "ptr/qword";
                    if (size >= 16) type_guess = "vector/xmm";

                    std::cout << "      Offset 0x" << std::hex << offset
                              << ": Size " << std::dec << size
                              << " (" << type_guess << ") - "
                              << accesses.size() << " refs" << std::endl;
                }
            }
        }

        if (!assigns.empty()) {
            std::vector<Analysis::Assignment> sorted_assigns = assigns;
            std::sort(sorted_assigns.begin(), sorted_assigns.end(),
                [](const Analysis::Assignment& a, const Analysis::Assignment& b) {
                    return a.addr.value < b.addr.value;
                });

            for (const auto& ref : sorted_assigns) {
                std::cout << "    - 0x" << std::hex << ref.addr.value
                          << ": " << ref.desc
                          << (ref.is_heuristic ? " [Heuristic]" : "") << std::endl;
            }
        } else {
            std::cout << "    (No direct assignments detected)" << std::endl;
        }
    }

    std::cout << "\n[Summary] Displayed: " << std::dec << displayed_count
              << " | Filtered (False Positives): " << filtered_count << std::endl;

    return 0;
}
