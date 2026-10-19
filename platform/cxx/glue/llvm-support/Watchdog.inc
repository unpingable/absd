//===- ABSD/Watchdog.inc - watchdog on the ABSD C kit -----------*- C++ -*-===//
// Included by lib/Support/Watchdog.cpp in place of Unix/Watchdog.inc when
// LLVM_ABSD_KIT is defined (cxx/patches/llvm/0004). The Unix watchdog arms
// alarm(), whose SIGALRM kills a hung process. ABSD delivers no signals
// and the kit has no alarm, so the watchdog does nothing: a hung process is
// ended by its parent (the runtime's kill hook), not by itself. LLVM arms
// it only around stack-trace symbolization, which ABSD never runs.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

namespace llvm {
namespace sys {
Watchdog::Watchdog(unsigned int seconds) { (void)seconds; }
Watchdog::~Watchdog() {}
} // namespace sys
} // namespace llvm
