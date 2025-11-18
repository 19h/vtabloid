cmake_minimum_required(VERSION 3.15)
project(VTableAnalyzerCore LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configure Capstone - Disable unnecessary components to speed up build
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)

include(FetchContent)

FetchContent_Declare(
        capstone
        GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
        GIT_TAG        6.0.0-Alpha5
)
FetchContent_MakeAvailable(capstone)

add_executable(vtable_analyzer
        src/main.cpp
        src/pe/pe_loader.cpp
        src/analysis/vtable_scanner.cpp
        src/analysis/cfg.cpp
        src/analysis/dataflow.cpp
        src/analysis/structure.cpp
)

target_include_directories(vtable_analyzer PRIVATE src)
target_include_directories(vtable_analyzer SYSTEM PRIVATE ${capstone_SOURCE_DIR}/include)
target_link_libraries(vtable_analyzer PRIVATE capstone)

# CRITICAL FIX: Apply strict compilation flags ONLY to the vtable_analyzer target.
# Do NOT use add_compile_options() as it pollutes the Capstone C build, causing
# failures due to strict C++ warnings being applied to C code (e.g., -Wc11-extensions).
if(MSVC)
    target_compile_options(vtable_analyzer PRIVATE /W4 /WX /permissive- /Zc:__cplusplus /O2 /Oi)
else()
    target_compile_options(vtable_analyzer PRIVATE
            -Wall -Wextra -Werror -pedantic
            -Wconversion -Wsign-conversion -Wshadow
            -Wunused -Wformat=2 -O3 -march=native
    )
endif()