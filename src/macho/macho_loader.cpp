#include "macho_loader.hpp"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace MachO {

    MachoLoader::MachoLoader(const std::string& filepath) : filepath_(filepath) {}

    uint32_t MachoLoader::swap32(uint32_t val) const {
        if (!is_big_endian_) return val;
        return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
               ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
    }

    bool MachoLoader::load() {
        std::ifstream file(filepath_, std::ios::binary | std::ios::ate);
        if (!file) return false;

        auto size = file.tellg();
        if (size <= 0) return false;

        std::vector<uint8_t> raw_data(static_cast<size_t>(size));
        file.seekg(0);
        file.read(reinterpret_cast<char*>(raw_data.data()), size);

        if (raw_data.size() < 4) return false;

        uint32_t magic;
        std::memcpy(&magic, raw_data.data(), 4);

        if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
            is_big_endian_ = true; // Fat headers are always BE
            return load_fat(raw_data);
        } else if (magic == MH_MAGIC_64) {
            is_big_endian_ = false;
            return load_thin(raw_data);
        } else if (magic == MH_CIGAM_64) {
            is_big_endian_ = true;
            return load_thin(raw_data);
        }

        return false;
    }

    bool MachoLoader::load_fat(const std::vector<uint8_t>& raw_data) {
        if (raw_data.size() < sizeof(fat_header)) return false;

        const auto* hdr = reinterpret_cast<const fat_header*>(raw_data.data());
        uint32_t nfat = swap32(hdr->nfat_arch);

        if (raw_data.size() < sizeof(fat_header) + nfat * sizeof(fat_arch)) return false;

        const auto* archs = reinterpret_cast<const fat_arch*>(raw_data.data() + sizeof(fat_header));

        for (uint32_t i = 0; i < nfat; ++i) {
            uint32_t cputype = swap32(archs[i].cputype);

            if (cputype == CPU_TYPE_X86_64) {
                uint32_t offset = swap32(archs[i].offset);
                uint32_t size = swap32(archs[i].size);

                if (offset + size > raw_data.size()) return false;

                // Extract the slice
                std::vector<uint8_t> slice(size);
                std::memcpy(slice.data(), raw_data.data() + offset, size);

                // Reset endianness for the slice (usually LE for x64)
                // We check the magic of the slice
                if (slice.size() < 4) return false;
                uint32_t slice_magic;
                std::memcpy(&slice_magic, slice.data(), 4);

                if (slice_magic == MH_MAGIC_64) is_big_endian_ = false;
                else if (slice_magic == MH_CIGAM_64) is_big_endian_ = true;
                else return false;

                return load_thin(slice);
            }
        }

        std::cerr << "[!] No x64 slice found in Fat Binary." << std::endl;
        return false;
    }

    bool MachoLoader::load_thin(const std::vector<uint8_t>& raw_data) {
        buffer_ = raw_data; // Take ownership of the data

        if (buffer_.size() < sizeof(mach_header_64)) return false;
        const auto* hdr = reinterpret_cast<const mach_header_64*>(buffer_.data());

        if (swap32(hdr->cputype) != CPU_TYPE_X86_64) return false;

        uint32_t ncmds = swap32(hdr->ncmds);
        uint32_t offset = sizeof(mach_header_64);

        image_base_ = UINT64_MAX;

        for (uint32_t i = 0; i < ncmds; ++i) {
            if (offset + sizeof(load_command) > buffer_.size()) break;

            const auto* lc = reinterpret_cast<const load_command*>(buffer_.data() + offset);
            uint32_t cmd = swap32(lc->cmd);
            uint32_t cmdsize = swap32(lc->cmdsize);

            if (cmdsize == 0 || offset + cmdsize > buffer_.size()) break;

            if (cmd == LC_SEGMENT_64) {
                const auto* seg = reinterpret_cast<const segment_command_64*>(lc);
                uint64_t vmaddr = is_big_endian_ ? __builtin_bswap64(seg->vmaddr) : seg->vmaddr;
                uint32_t nsects = swap32(seg->nsects);
                uint32_t initprot = swap32(seg->initprot);

                if (vmaddr < image_base_ && vmaddr != 0) image_base_ = vmaddr;

                uint32_t sect_offset = offset + static_cast<uint32_t>(sizeof(segment_command_64));
                for (uint32_t j = 0; j < nsects; ++j) {
                    if (sect_offset + sizeof(section_64) > offset + cmdsize) break;

                    const auto* sect = reinterpret_cast<const section_64*>(buffer_.data() + sect_offset);

                    Common::Section s;
                    char name[17] = {0};
                    std::memcpy(name, sect->sectname, 16);
                    s.name = name;

                    uint64_t addr = is_big_endian_ ? __builtin_bswap64(sect->addr) : sect->addr;
                    uint64_t size = is_big_endian_ ? __builtin_bswap64(sect->size) : sect->size;
                    uint32_t foff = swap32(sect->offset);

                    s.rva = Common::RVA{static_cast<uint32_t>(addr)}; // Temp absolute VA
                    s.virtual_size = static_cast<uint32_t>(size);
                    s.raw_ptr = Common::FileOffset{foff};
                    s.raw_size = static_cast<uint32_t>(size);

                    s.is_readable = (initprot & VM_PROT_READ) != 0;
                    s.is_writable = (initprot & VM_PROT_WRITE) != 0;
                    s.is_executable = (initprot & VM_PROT_EXECUTE) != 0;

                    sections_.push_back(s);
                    sect_offset += sizeof(section_64);
                }
            }
            else if (cmd == LC_MAIN) {
                const auto* ep = reinterpret_cast<const entry_point_command*>(lc);
                uint64_t entryoff = is_big_endian_ ? __builtin_bswap64(ep->entryoff) : ep->entryoff;
                // LC_MAIN gives file offset. We need to map this to RVA later.
                // Store file offset temporarily in RVA value, fix up after loop.
                entry_point_ = Common::RVA{static_cast<uint32_t>(entryoff)};
            }
            else if (cmd == LC_UNIXTHREAD) {
                // Flavor 4 is x86_THREAD_STATE64
                // Header: cmd(4), cmdsize(4), flavor(4), count(4)
                if (cmdsize >= 16 + sizeof(x86_thread_state64_t)) {
                    uint32_t flavor;
                    std::memcpy(&flavor, buffer_.data() + offset + 8, 4);
                    flavor = swap32(flavor);

                    if (flavor == 4) { // x86_THREAD_STATE64
                        const auto* state = reinterpret_cast<const x86_thread_state64_t*>(buffer_.data() + offset + 16);
                        uint64_t rip = is_big_endian_ ? __builtin_bswap64(state->rip) : state->rip;
                        // This is a VA.
                        entry_point_ = Common::RVA{static_cast<uint32_t>(rip)};
                    }
                }
            }

            offset += cmdsize;
        }

        if (image_base_ == UINT64_MAX) image_base_ = 0;

        // Fixup RVAs (subtract ImageBase)
        for (auto& sec : sections_) {
            sec.rva = Common::RVA{sec.rva.value - static_cast<uint32_t>(image_base_)};
        }

        // Fixup Entry Point
        // If it was LC_MAIN, it's a file offset. Map to RVA.
        // If it was LC_UNIXTHREAD, it's a VA. Map to RVA.
        // We need to distinguish.
        // Heuristic: If entry_point is small (likely offset) vs large (likely VA).
        // Better: Check if entry_point matches a file offset in a section.

        // Try interpreting as VA first
        if (entry_point_.value >= image_base_) {
             entry_point_ = Common::RVA{entry_point_.value - static_cast<uint32_t>(image_base_)};
        } else {
            // Try interpreting as File Offset
            auto rva = offset_to_rva(Common::FileOffset{entry_point_.value});
            if (rva) {
                entry_point_ = *rva;
            }
        }

        view_ = std::make_unique<Common::BinaryView>(buffer_, image_base_);
        return true;
    }

    std::optional<Common::FileOffset> MachoLoader::rva_to_offset(Common::RVA rva) const {
        for (const auto& sec : sections_) {
            if (sec.contains(rva)) {
                uint32_t delta = rva.value - sec.rva.value;
                if (delta < sec.raw_size) return sec.raw_ptr + delta;
            }
        }
        return std::nullopt;
    }

    std::optional<Common::RVA> MachoLoader::offset_to_rva(Common::FileOffset offset) const {
        for (const auto& sec : sections_) {
            if (offset.value >= sec.raw_ptr.value && offset.value < sec.raw_ptr.value + sec.raw_size) {
                return sec.rva + (offset.value - sec.raw_ptr.value);
            }
        }
        return std::nullopt;
    }

    std::optional<uint64_t> MachoLoader::read_ptr_at(Common::RVA rva) const {
        auto off = rva_to_offset(rva);
        if (!off) return std::nullopt;
        auto val = view_->read_ptr(*off, arch_);
        if (val && is_big_endian_) {
            return __builtin_bswap64(*val);
        }
        return val;
    }
}
