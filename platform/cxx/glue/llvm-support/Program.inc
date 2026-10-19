//===- ABSD/Program.inc - program execution on the ABSD C kit ---*- C++ -*-===//
// Included by lib/Support/Program.cpp in place of Unix/Program.inc when
// LLVM_ABSD_KIT is defined (cxx/patches/llvm/0004). The kit and its POSIX
// adapter provide no fork, exec, posix_spawn or wait (C-INTERFACE.md
// section 10). Starting a program needs authority the C kit does not hand
// a C program (the runtime's spawn hook takes an image the caller holds and
// a handle vector; no adapter turns that into posix_spawn), so execution
// is refused, never approximated: Execute reports failure with a message,
// Wait has nothing to wait for. Clang runs cc1 in its own process
// (CLANG_SPAWN_CC1=OFF), so `clang -c` needs none of this; a link through
// the driver (which would start ld.lld) is refused and lld is run directly.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//===----------------------------------------------------------------------===//

#include "llvm/Support/Program.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include <stdlib.h>

using namespace llvm;
using namespace sys;

ProcessInfo::ProcessInfo() : Pid(0), ReturnCode(0) {}

// The lookup is the Unix one (PATH, or the given directories); it names a
// file, it starts nothing. sh(1) on ABSD runs what it finds.
ErrorOr<std::string> sys::findProgramByName(StringRef Name, ArrayRef<StringRef> Paths) {
  assert(!Name.empty() && "Must have a name!");
  if (Name.contains('/'))
    return std::string(Name);
  SmallVector<StringRef, 16> EnvironmentPaths;
  if (Paths.empty())
    if (const char *PathEnv = std::getenv("PATH")) {
      SplitString(PathEnv, EnvironmentPaths, ":");
      Paths = EnvironmentPaths;
    }
  for (auto Path : Paths) {
    if (Path.empty())
      continue;
    SmallString<128> FilePath(Path);
    sys::path::append(FilePath, Name);
    if (sys::fs::can_execute(FilePath.c_str()))
      return std::string(FilePath);
  }
  return errc::no_such_file_or_directory;
}

static bool Execute(ProcessInfo &PI, StringRef Program, ArrayRef<StringRef> Args,
                    std::optional<ArrayRef<StringRef>> Env,
                    ArrayRef<std::optional<StringRef>> Redirects, unsigned MemoryLimit,
                    std::string *ErrMsg, BitVector *AffinityMask) {
  (void)PI; (void)Args; (void)Env; (void)Redirects; (void)MemoryLimit; (void)AffinityMask;
  if (ErrMsg)
    *ErrMsg = ("cannot execute '" + Program +
               "': starting a program is not available to programs on the ABSD C kit")
                  .str();
  return false;
}

ProcessInfo llvm::sys::Wait(const ProcessInfo &PI, std::optional<unsigned> SecondsToWait,
                            std::string *ErrMsg, std::optional<ProcessStatistics> *ProcStat,
                            bool Polling) {
  (void)SecondsToWait; (void)Polling;
  ProcessInfo WaitResult = PI;
  WaitResult.ReturnCode = -1;
  if (ProcStat)
    ProcStat->reset();
  if (ErrMsg)
    *ErrMsg = "no child process: the ABSD C kit starts none";
  return WaitResult;
}

std::error_code llvm::sys::ChangeStdinMode(fs::OpenFlags Flags) { return std::error_code(); }
std::error_code llvm::sys::ChangeStdoutMode(fs::OpenFlags Flags) { return std::error_code(); }
std::error_code llvm::sys::ChangeStdinToBinary() { return std::error_code(); }
std::error_code llvm::sys::ChangeStdoutToBinary() { return std::error_code(); }

std::error_code llvm::sys::writeFileWithEncoding(StringRef FileName, StringRef Contents,
                                                 WindowsEncodingMethod Encoding) {
  std::error_code EC;
  llvm::raw_fd_ostream OS(FileName, EC, llvm::sys::fs::OpenFlags::OF_TextWithCRLF);
  if (EC)
    return EC;
  OS << Contents;
  if (OS.has_error())
    return make_error_code(errc::io_error);
  return EC;
}

// The startup record bounds a command line: at most 32 arguments in a
// record of at most 8192 bytes (C-INTERFACE.md section 2). Response files
// are used beyond that.
bool llvm::sys::commandLineFitsWithinSystemLimits(StringRef Program, ArrayRef<StringRef> Args) {
  if (Args.size() > 32)
    return false;
  size_t Length = Program.size() + 2;
  for (StringRef Arg : Args)
    Length += Arg.size() + 2;
  return Length <= 8192 - 64;
}
