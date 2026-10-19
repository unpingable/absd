//===- ABSD/Memory.inc - memory blocks on the ABSD C kit --------*- C++ -*-===//
// Included by lib/Support/Memory.cpp in place of Unix/Memory.inc when
// LLVM_ABSD_KIT is defined (cxx/patches/llvm/0004). The kit has no mmap or
// mprotect (C-INTERFACE.md section 3); its allocator takes page-granular
// zeroed memory from the process's heap window through the runtime, and
// heap pages are never executable. So a block is a page-aligned heap
// allocation: readable and writable blocks are given; executable memory,
// or a block without both read and write, is refused (ENOTSUP), since
// changing page protection is not available. Clang and LLD only write
// object files; nothing here is reached by a compile or a link (JIT only).
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#include "llvm/Support/Alignment.h"
#include "llvm/Support/DataTypes.h"
#include "llvm/Support/Memory.h"
#include "llvm/Support/Process.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

namespace llvm {
namespace sys {

static bool absdProtectionGiven(unsigned PFlags) {
  return (PFlags & Memory::MF_RWE_MASK) == (Memory::MF_READ | Memory::MF_WRITE);
}

MemoryBlock Memory::allocateMappedMemory(size_t NumBytes, const MemoryBlock *const NearBlock,
                                         unsigned PFlags, std::error_code &EC) {
  (void)NearBlock;
  EC = std::error_code();
  if (NumBytes == 0)
    return MemoryBlock();
  if (!absdProtectionGiven(PFlags)) {
    EC = std::error_code(ENOTSUP, std::generic_category());
    return MemoryBlock();
  }
  static const size_t PageSize = Process::getPageSizeEstimate();
  const size_t NumPages = (NumBytes + PageSize - 1) / PageSize;
  void *Addr = aligned_alloc(PageSize, PageSize * NumPages);
  if (!Addr) {
    EC = std::error_code(ENOMEM, std::generic_category());
    return MemoryBlock();
  }
  memset(Addr, 0, PageSize * NumPages);   // a mapping is zeroed
  MemoryBlock Result;
  Result.Address = Addr;
  Result.AllocatedSize = PageSize * NumPages;
  Result.Flags = PFlags;
  return Result;
}

std::error_code Memory::releaseMappedMemory(MemoryBlock &M) {
  if (M.Address == nullptr || M.AllocatedSize == 0)
    return std::error_code();
  free(M.Address);
  M.Address = nullptr;
  M.AllocatedSize = 0;
  return std::error_code();
}

std::error_code Memory::protectMappedMemory(const MemoryBlock &M, unsigned Flags) {
  if (M.Address == nullptr || M.AllocatedSize == 0)
    return std::error_code();
  if (!Flags)
    return std::error_code(EINVAL, std::generic_category());
  if (!absdProtectionGiven(Flags))
    return std::error_code(ENOTSUP, std::generic_category());
  return std::error_code();
}

void Memory::InvalidateInstructionCache(const void *Addr, size_t Len) {}

} // namespace sys
} // namespace llvm
