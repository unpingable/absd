// A condition-variable wait in a one-task process: nobody can notify.
// Expected: "condvar wait", then the abort message, status 134.
#include <condition_variable>
#include <cstdio>
#include <mutex>
int main() {
  std::mutex m;
  std::condition_variable cv;
  std::unique_lock<std::mutex> l(m);
  std::printf("condvar wait\n"); std::fflush(stdout);
  cv.wait(l);
  std::printf("unreachable\n");
  return 0;
}
