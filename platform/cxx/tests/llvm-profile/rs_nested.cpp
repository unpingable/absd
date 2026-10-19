// random_shuffle.cpp's default generator: __rs_default's constructor takes a
// lock and ignores the result, so a second generator while one is alive
// must stop here. Expected: "rs nested", then the abort message naming the
// relock, status 134.
#include <algorithm>
#include <cstdio>
int main() {
  std::printf("rs nested\n"); std::fflush(stdout);
  std::__rs_default a = std::__rs_get();
  std::__rs_default b = std::__rs_get();
  std::printf("unreachable %u\n", a() ^ b());
  return 0;
}
