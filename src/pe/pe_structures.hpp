#pragma once
#include <cstdint>

namespace PE {
    constexpr uint16_t DOS_MAGIC = 0x5A4D;
    constexpr uint32_t PE_MAGIC = 0x00004550;
    constexpr uint16_t MACHINE_I386 = 0x014c;
    constexpr uint16_t MACHINE_AMD64 = 0x8664;

    struct IMAGE_DOS_HEADER {
        uint16_t e_magic;
        uint16_t e_res[29];
        uint32_t e_lfanew;
    };

    struct IMAGE_FILE_HEADER {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    };

    struct IMAGE_DATA_DIRECTORY {
        uint32_t VirtualAddress;
        uint32_t Size;
    };

    constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
    constexpr int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
    constexpr int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    constexpr int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
    constexpr int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;

    struct IMAGE_OPTIONAL_HEADER32 {
        uint16_t Magic;
        uint8_t  MajorLinkerVersion;
        uint8_t  MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint32_t BaseOfData;
        uint32_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint32_t SizeOfStackReserve;
        uint32_t SizeOfStackCommit;
        uint32_t SizeOfHeapReserve;
        uint32_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    struct IMAGE_OPTIONAL_HEADER64 {
        uint16_t Magic;
        uint8_t  MajorLinkerVersion;
        uint8_t  MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint;
        uint32_t BaseOfCode;
        uint64_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        uint16_t DllCharacteristics;
        uint64_t SizeOfStackReserve;
        uint64_t SizeOfStackCommit;
        uint64_t SizeOfHeapReserve;
        uint64_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        uint32_t NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    };

    struct IMAGE_SECTION_HEADER {
        uint8_t  Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLinenumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLinenumbers;
        uint32_t Characteristics;
    };

    struct IMAGE_RUNTIME_FUNCTION_ENTRY {
        uint32_t BeginAddress;
        uint32_t EndAddress;
        uint32_t UnwindInfoAddress;
    };

    constexpr uint32_t SCN_CNT_CODE = 0x00000020;
    constexpr uint32_t SCN_MEM_EXECUTE = 0x20000000;
    constexpr uint32_t SCN_MEM_READ    = 0x40000000;
    constexpr uint32_t SCN_MEM_WRITE   = 0x80000000;
}