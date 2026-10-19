//===- ABSD/Signals.inc - signal handling on the ABSD C kit -----*- C++ -*-===//
// Included by lib/Support/Signals.cpp in place of Unix/Signals.inc when
// LLVM_ABSD_KIT is defined (cxx/patches/llvm/0004). ABSD delivers no signal
// to a process (C-INTERFACE.md section 10): a fault ends the process in the
// kernel and its parent sees -1000 - vector; abort() is raise(SIGABRT),
// which ends it with status 134 without running anything. So nothing here
// installs a handler, there is no alternate stack, and no stack trace can
// be printed (no unwinder, .eh_frame is discarded by absd-c.ld).
// What is kept: the registrations, so that the explicit entry points that
// do run (RunInterruptHandlers, CleanupOnSignal from CrashRecoveryContext)
// still remove the files the program asked to have removed.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#include "llvm/ADT/STLExtras.h"
#include "llvm/Support/ExitCodes.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <string>
#include <vector>
#include <stdlib.h>

using namespace llvm;

namespace {
// One task: a plain list, no atomics or locks are needed.
std::vector<std::string> &filesToRemove() {
  static std::vector<std::string> Files;
  return Files;
}
void (*InterruptFunction)() = nullptr;
void (*InfoSignalFunction)() = nullptr;
void (*OneShotPipeSignalFunction)() = nullptr;
StringRef Argv0;
} // namespace

static void RemoveFilesToRemove() {
  std::vector<std::string> &Files = filesToRemove();
  for (const std::string &F : Files) {
    // Only regular files are removed, as on Unix.
    sys::fs::file_status Status;
    if (sys::fs::status(F, Status) || !sys::fs::is_regular_file(Status))
      continue;
    sys::fs::remove(F, /*IgnoreNonExisting=*/true);
  }
  Files.clear();
}

void sys::unregisterHandlers() {}

void sys::CleanupOnSignal(uintptr_t Context) {
  (void)Context;
  RemoveFilesToRemove();
  llvm::sys::RunSignalHandlers();
}

void llvm::sys::RunInterruptHandlers() { RemoveFilesToRemove(); }

void llvm::sys::SetInterruptFunction(void (*IF)()) { InterruptFunction = IF; }
void llvm::sys::SetInfoSignalFunction(void (*Handler)()) { InfoSignalFunction = Handler; }
void llvm::sys::SetOneShotPipeSignalFunction(void (*Handler)()) { OneShotPipeSignalFunction = Handler; }

void llvm::sys::DefaultOneShotPipeSignalHandler() { exit(EX_IOERR); }

bool llvm::sys::RemoveFileOnSignal(StringRef Filename, std::string *ErrMsg) {
  (void)ErrMsg;
  filesToRemove().push_back(Filename.str());
  return false;
}

void llvm::sys::DontRemoveFileOnSignal(StringRef Filename) {
  std::vector<std::string> &Files = filesToRemove();
  auto It = llvm::find(llvm::reverse(Files), Filename);
  if (It != Files.rend())
    Files.erase(It.base() - 1);
}

void llvm::sys::AddSignalHandler(sys::SignalHandlerCallback FnPtr, void *Cookie) {
  insertSignalHandler(FnPtr, Cookie);
}

// Signals.cpp's symbolizer path calls these; there are no modules to find
// (one static image) and no frames to report.
static bool findModulesAndOffsets(void **StackTrace, int Depth, const char **Modules,
                                  intptr_t *Offsets, const char *MainExecutableName,
                                  StringSaver &StrPool) {
  return false;
}
static bool printMarkupContext(raw_ostream &OS, const char *MainExecutableName) {
  return false;
}

void llvm::sys::PrintStackTrace(raw_ostream &OS, int Depth) {
  (void)Depth;
  OS << "(no stack trace: ABSD keeps no unwind tables and delivers no signals)\n";
}

void llvm::sys::DisableSystemDialogsOnCrash() {}

void llvm::sys::PrintStackTraceOnErrorSignal(StringRef A0, bool DisableCrashReporting) {
  (void)DisableCrashReporting;
  ::Argv0 = A0;
}
