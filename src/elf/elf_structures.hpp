#pragma once
#include <cstdint>

namespace ELF {

    // ELF Magic: 0x7F 'E' 'L' 'F'
    constexpr uint8_t ELFMAG0 = 0x7F;
    constexpr uint8_t ELFMAG1 = 'E';
    constexpr uint8_t ELFMAG2 = 'L';
    constexpr uint8_t ELFMAG3 = 'F';

    // File Class
    constexpr uint8_t ELFCLASS32 = 1;
    constexpr uint8_t ELFCLASS64 = 2;

    // Data Encoding
    constexpr uint8_t ELFDATA2LSB = 1; // Little Endian

    // Machine
    constexpr uint16_t EM_386 = 3;
    constexpr uint16_t EM_X86_64 = 62;

    // Section Types
    constexpr uint32_t SHT_PROGBITS = 1;
    constexpr uint32_t SHT_NOBITS = 8;

    // Section Flags
    constexpr uint64_t SHF_WRITE = 0x1;
    constexpr uint64_t SHF_ALLOC = 0x2;
    constexpr uint64_t SHF_EXECINSTR = 0x4;

    // 32-bit Header
    struct Elf32_Ehdr {
        unsigned char e_ident[16];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint32_t e_entry;
        uint32_t e_phoff;
        uint32_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
    };

    // 64-bit Header
    struct Elf64_Ehdr {
        unsigned char e_ident[16];
        uint16_t e_type;
        uint16_t e_machine;
        uint32_t e_version;
        uint64_t e_entry;
        uint64_t e_phoff;
        uint64_t e_shoff;
        uint32_t e_flags;
        uint16_t e_ehsize;
        uint16_t e_phentsize;
        uint16_t e_phnum;
        uint16_t e_shentsize;
        uint16_t e_shnum;
        uint16_t e_shstrndx;
    };

    // 32-bit Section Header
    struct Elf32_Shdr {
        uint32_t sh_name;
        uint32_t sh_type;
        uint32_t sh_flags;
        uint32_t sh_addr;
        uint32_t sh_offset;
        uint32_t sh_size;
        uint32_t sh_link;
        uint32_t sh_info;
        uint32_t sh_addralign;
        uint32_t sh_entsize;
    };

    // 64-bit Section Header
    struct Elf64_Shdr {
        uint32_t sh_name;
        uint32_t sh_type;
        uint64_t sh_flags;
        uint64_t sh_addr;
        uint64_t sh_offset;
        uint64_t sh_size;
        uint32_t sh_link;
        uint32_t sh_info;
        uint64_t sh_addralign;
        uint64_t sh_entsize;
    };
}
