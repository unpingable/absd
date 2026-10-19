# CMake toolchain for LLVM, Clang and LLD as ABSD programs
# (scripts/build-llvm-kit.sh). Host clang 18 compiles for
# x86_64-unknown-none-elf; the build script passes the C kit's own compile
# flags (read from the kit's bin/absd-cc, as scripts/build-cxx-runtime.sh
# does) as CMAKE_C_FLAGS/CMAKE_CXX_FLAGS. Every executable, including
# CMake's configuration probes, is linked by cxx/bin/absd-llvm-link, the
# kit's fixed link (absd-c.ld, crt0, libc++, the POSIX adapter, libabs,
# Picolibc, builtins): a probe for a function the kit does not define
# fails to link, so the configuration records what the kit really offers.
set(CMAKE_SYSTEM_NAME ABSD)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
set(CMAKE_C_COMPILER clang-18)
set(CMAKE_CXX_COMPILER clang++-18)
set(CMAKE_ASM_COMPILER clang-18)
set(CMAKE_C_COMPILER_TARGET x86_64-unknown-none-elf)
set(CMAKE_CXX_COMPILER_TARGET x86_64-unknown-none-elf)
set(CMAKE_ASM_COMPILER_TARGET x86_64-unknown-none-elf)
set(CMAKE_AR llvm-ar-18 CACHE FILEPATH "")
set(CMAKE_RANLIB llvm-ranlib-18 CACHE FILEPATH "")
set(CMAKE_NM llvm-nm-18 CACHE FILEPATH "")
set(CMAKE_OBJCOPY llvm-objcopy-18 CACHE FILEPATH "")
set(CMAKE_STRIP llvm-strip-18 CACHE FILEPATH "")
# ABSD_LINK is the link command with its kit, runtime and adapter
# arguments (set by the build script); probes see it too.
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ABSD_LINK)
set(CMAKE_C_LINK_EXECUTABLE "${ABSD_LINK} <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
set(CMAKE_CXX_LINK_EXECUTABLE "${ABSD_LINK} <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
