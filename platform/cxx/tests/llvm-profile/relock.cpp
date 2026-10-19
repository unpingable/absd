// std::mutex locked twice by the one task: a self-deadlock. Expected: the
// line "relock", then libc++'s abort message naming the relock on stderr,
// status 134.
#include <cstdio>
#include <mutex>
int main() {
  static std::mutex m;
  std::printf("relock\n"); std::fflush(stdout);
  m.lock();
  m.lock();
  std::printf("unreachable\n");
  return 0;
}
