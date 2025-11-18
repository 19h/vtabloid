#pragma once
#include <cstdint>

namespace MachO {

    // Magic Numbers
    constexpr uint32_t MH_MAGIC_64 = 0xFEEDFACF;
    constexpr uint32_t MH_CIGAM_64 = 0xCFFAEDFE;
    constexpr uint32_t FAT_MAGIC   = 0xCAFEBABE;
    constexpr uint32_t FAT_CIGAM   = 0xBEBAFECA;

    // CPU Types
    constexpr uint32_t CPU_ARCH_ABI64 = 0x01000000;
    constexpr uint32_t CPU_TYPE_X86   = 7;
    constexpr uint32_t CPU_TYPE_X86_64 = (CPU_TYPE_X86 | CPU_ARCH_ABI64);

    // Load Commands
    constexpr uint32_t LC_SEGMENT_64 = 0x19;
    constexpr uint32_t LC_SYMTAB     = 0x2;
    constexpr uint32_t LC_DYSYMTAB   = 0xB;
    constexpr uint32_t LC_UNIXTHREAD = 0x5;
    constexpr uint32_t LC_MAIN       = 0x80000028;

    // Protection Flags
    constexpr uint32_t VM_PROT_READ    = 0x1;
    constexpr uint32_t VM_PROT_WRITE   = 0x2;
    constexpr uint32_t VM_PROT_EXECUTE = 0x4;

    // Section Flags
    constexpr uint32_t S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
    constexpr uint32_t S_ATTR_SOME_INSTRUCTIONS = 0x00000400;

    struct mach_header_64 {
        uint32_t magic;
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t filetype;
        uint32_t ncmds;
        uint32_t sizeofcmds;
        uint32_t flags;
        uint32_t reserved;
    };

    struct load_command {
        uint32_t cmd;
        uint32_t cmdsize;
    };

    struct segment_command_64 {
        uint32_t cmd;
        uint32_t cmdsize;
        char     segname[16];
        uint64_t vmaddr;
        uint64_t vmsize;
        uint64_t fileoff;
        uint64_t filesize;
        uint32_t maxprot;
        uint32_t initprot;
        uint32_t nsects;
        uint32_t flags;
    };

    struct section_64 {
        char     sectname[16];
        char     segname[16];
        uint64_t addr;
        uint64_t size;
        uint32_t offset;
        uint32_t align;
        uint32_t reloff;
        uint32_t nreloc;
        uint32_t flags;
        uint32_t reserved1;
        uint32_t reserved2;
        uint32_t reserved3;
    };

    struct entry_point_command {
        uint32_t cmd;
        uint32_t cmdsize;
        uint64_t entryoff;
        uint64_t stacksize;
    };

    // Fat Binary Structures
    struct fat_header {
        uint32_t magic;
        uint32_t nfat_arch;
    };

    struct fat_arch {
        uint32_t cputype;
        uint32_t cpusubtype;
        uint32_t offset;
        uint32_t size;
        uint32_t align;
    };

    // Thread State for LC_UNIXTHREAD (x86_64)
    // Flavor 4 (x86_THREAD_STATE64)
    struct x86_thread_state64_t {
        uint64_t rax; uint64_t rbx; uint64_t rcx; uint64_t rdx;
        uint64_t rdi; uint64_t rsi; uint64_t rbp; uint64_t rsp;
        uint64_t r8;  uint64_t r9;  uint64_t r10; uint64_t r11;
        uint64_t r12; uint64_t r13; uint64_t r14; uint64_t r15;
        uint64_t rip; uint64_t rflags; uint64_t cs; uint64_t fs; uint64_t gs;
    };
}
