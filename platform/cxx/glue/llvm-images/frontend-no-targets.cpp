//===- frontend-no-targets.cpp - a front-end-only clang image -------------===//
// The scout's split alternative (section 4): `cc1 -emit-llvm-bc` in one
// image, `llc -filetype=obj` in another. Linked with cc1-main.cpp into the
// front-end image in place of LLVM's X86 target libraries: cc1_main's
// llvm::InitializeAll*() then registers no target, so no LLVM code
// generator is reachable and --gc-sections drops it. Clang's own target
// description (clangBasic's X86 TargetInfo, which sets the data layout and
// predefined macros) is unaffected. A request that needs a code generator
// (-emit-obj, -S) fails with clang's "unable to create target" error; the
// bitcode path (-emit-llvm-bc, -emit-llvm) does not need one at -O0.
// SPDX-License-Identifier: Apache-2.0
//===----------------------------------------------------------------------===//

extern "C" {
void LLVMInitializeX86TargetInfo() {}
void LLVMInitializeX86Target() {}
void LLVMInitializeX86TargetMC() {}
void LLVMInitializeX86AsmPrinter() {}
void LLVMInitializeX86AsmParser() {}
void LLVMInitializeX86Disassembler() {}
void LLVMInitializeX86TargetMCA() {}
}
