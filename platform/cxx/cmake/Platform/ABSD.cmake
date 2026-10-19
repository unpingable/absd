# CMake platform for programs built against the ABSD C kit
# (cxx/absd-llvm-toolchain.cmake). ABSD is a Unix-style personality in
# userspace (docs/C-INTERFACE.md): Unix paths and archive naming, static
# executables only (no shared objects, no dynamic loader, CPA-063).
include(Platform/UnixPaths)
set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS FALSE)
set(CMAKE_EXECUTABLE_SUFFIX "")
set(CMAKE_STATIC_LIBRARY_PREFIX "lib")
set(CMAKE_STATIC_LIBRARY_SUFFIX ".a")
