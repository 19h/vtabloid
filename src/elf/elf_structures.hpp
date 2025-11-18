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
    constexpr uint32_t SHT_SYMTAB   = 2;
    constexpr uint32_t SHT_RELA     = 4;     // Relocation with addend
    constexpr uint32_t SHT_NOBITS   = 8;
    constexpr uint32_t SHT_REL      = 9;     // Relocation no addend
    constexpr uint32_t SHT_DYNSYM   = 11;
    constexpr uint32_t SHT_INIT_ARRAY = 14;

    // Section Flags
    constexpr uint64_t SHF_WRITE     = 0x1;
    constexpr uint64_t SHF_ALLOC     = 0x2;
    constexpr uint64_t SHF_EXECINSTR = 0x4;

    // Relocation Types (x86_64)
    constexpr uint32_t R_X86_64_64        = 1;
    constexpr uint32_t R_X86_64_GLOB_DAT  = 6;
    constexpr uint32_t R_X86_64_JUMP_SLOT = 7;
    constexpr uint32_t R_X86_64_RELATIVE  = 8;

    // Helpers to decode r_info (ELF64)
    inline constexpr uint32_t ELF64_R_SYM(uint64_t r_info)  { return static_cast<uint32_t>(r_info >> 32); }
    inline constexpr uint32_t ELF64_R_TYPE(uint64_t r_info) { return static_cast<uint32_t>(r_info & 0xFFFFFFFFu); }

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

    // Relocation Entries
    struct Elf64_Rela {
        uint64_t r_offset; // Location to apply relocation (VA)
        uint64_t r_info;   // Symbol table index and type
        int64_t  r_addend; // Constant addend
    };

    struct Elf32_Rel {
        uint32_t r_offset;
        uint32_t r_info;
    };

    // Symbol Table Entries
    struct Elf64_Sym {
        uint32_t st_name;
        unsigned char st_info;
        unsigned char st_other;
        uint16_t st_shndx;
        uint64_t st_value;
        uint64_t st_size;
    };

    struct Elf32_Sym {
        uint32_t st_name;
        uint32_t st_value;
        uint32_t st_size;
        unsigned char st_info;
        unsigned char st_other;
        uint16_t st_shndx;
    };
}
