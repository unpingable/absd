// memory.cpp's shared_ptr lock pool: __sp_mut::lock ignores the lock's
// result, so a nested lock of the same pool slot must stop here rather than
// proceed as if locked. Expected: "sp_mut nested", then the abort message
// naming the relock, status 134.
#include <cstdio>
#include <memory>
int main() {
  int x = 0;
  std::printf("sp_mut nested\n"); std::fflush(stdout);
  std::__sp_mut& m = std::__get_sp_mut(&x);
  m.lock();
  m.lock();
  std::printf("unreachable\n");
  return 0;
}
