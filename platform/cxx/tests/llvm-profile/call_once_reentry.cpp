// std::call_once re-entered on the same flag from its own function
// (call_once.cpp waits on a condition variable while the flag is pending).
// Expected: "call_once reentry", then the abort message naming the
// condition-variable wait / re-entered call_once, status 134; never a spin.
#include <cstdio>
#include <mutex>
static std::once_flag flag;
static void again() { std::call_once(flag, again); }
int main() {
  std::printf("call_once reentry\n"); std::fflush(stdout);
  std::call_once(flag, again);
  std::printf("unreachable\n");
  return 0;
}
