//===- cc1-main.cpp - a cc1-only clang image for the ABSD C kit -----------===//
// The scout's first image-size alternative (section 4): clang's compiler
// proper without the driver. `cc1 ARGS` is `clang -cc1 ARGS` (a leading
// -cc1 is accepted and skipped; @response files are expanded as the driver
// would). Linked by scripts/build-llvm-kit.sh (step alternatives) from the
// same objects and archives as bin/clang-18, with this file in place of
// driver.cpp; everything the driver alone uses is then dropped by
// --gc-sections. Not a replacement for clang: there is no driver to turn
// `clang -c x.c` into cc1 arguments (`clang -### -c x.c` prints them).
// SPDX-License-Identifier: Apache-2.0
//===----------------------------------------------------------------------===//

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Allocator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/StringSaver.h"
#include <cstring>

extern int cc1_main(llvm::ArrayRef<const char *> Argv, const char *Argv0, void *MainAddr);

// MainAddr names an address inside the image (Unix uses it for dladdr;
// ABSD resolves argv[0] instead, cxx/patches/llvm/0005).
static void cc1ImageAnchor() {}

int main(int argc, const char **argv) {
  llvm::InitLLVM X(argc, argv);
  llvm::SmallVector<const char *, 256> Args(argv + 1, argv + argc);
  llvm::BumpPtrAllocator A;
  llvm::StringSaver Saver(A);
  if (!llvm::cl::ExpandResponseFiles(Saver, llvm::cl::TokenizeGNUCommandLine, Args))
    return 1;
  llvm::ArrayRef<const char *> Rest(Args);
  if (!Rest.empty() && std::strcmp(Rest.front(), "-cc1") == 0)
    Rest = Rest.drop_front();
  return cc1_main(Rest, argv[0], (void *)(intptr_t)&cc1ImageAnchor);
}
