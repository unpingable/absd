# CMake toolchain for the ABSD C++ runtime (scripts/build-cxx-runtime.sh):
# host clang 18 for x86_64-unknown-none-elf, static archives only. The
# compile flags are not set here: the build script passes the C kit's own
# flags (read from the kit's bin/absd-cc) as CMAKE_C_FLAGS/CMAKE_CXX_FLAGS.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(CMAKE_C_COMPILER clang-18)
set(CMAKE_CXX_COMPILER clang++-18)
set(CMAKE_ASM_COMPILER clang-18)
set(CMAKE_C_COMPILER_TARGET x86_64-unknown-none-elf)
set(CMAKE_CXX_COMPILER_TARGET x86_64-unknown-none-elf)
set(CMAKE_ASM_COMPILER_TARGET x86_64-unknown-none-elf)
set(CMAKE_AR llvm-ar-18 CACHE FILEPATH "")
set(CMAKE_RANLIB llvm-ranlib-18 CACHE FILEPATH "")
set(CMAKE_NM llvm-nm-18 CACHE FILEPATH "")
# Nothing is linked during configuration: there is no ABSD executable to run.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
