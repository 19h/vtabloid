#pragma once
#include <cstdint>

namespace Analysis::MSVC {

    // x86 RTTI (Direct VAs)
    struct RTTICompleteObjectLocator32 {
        uint32_t signature;      // 0
        uint32_t offset;
        uint32_t cdOffset;
        uint32_t pTypeDescriptor;          // VA
        uint32_t pClassHierarchyDescriptor; // VA
    };

    // x64 RTTI (Relative Offsets from ImageBase)
    struct RTTICompleteObjectLocator64 {
        uint32_t signature;      // 1
        uint32_t offset;
        uint32_t cdOffset;
        int32_t pTypeDescriptor;           // RVA
        int32_t pClassHierarchyDescriptor; // RVA
        int32_t pSelf;                     // RVA to this structure
    };

    struct RTTIClassHierarchyDescriptor {
        uint32_t signature;
        uint32_t attributes;
        uint32_t numBaseClasses;
        uint32_t pBaseClassArray; // VA or RVA depending on arch
    };

    struct TypeDescriptor {
        uintptr_t pVFTable; // Virtual Function Table for TypeDescriptor
        uintptr_t spare;
        char name[1];       // Mangled name
    };
}