// LLVM runtime profile, the paths that must work in one task: mutexes,
// recursive mutexes, try_lock, call_once (also nested on a different flag),
// unique_lock, shared_ptr atomic access (memory.cpp's __sp_mut pool),
// random_shuffle (random_shuffle.cpp's __rs_default lock), steady_clock.
// Expected: the lines in ok.expected, exit status 0.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <mutex>

static std::once_flag outer, inner;
static int once_runs = 0;

int main() {
  std::mutex m;
  m.lock();
  std::printf("try_lock held=%d\n", m.try_lock() ? 1 : 0);
  m.unlock();
  { std::lock_guard<std::mutex> g(m); }
  std::recursive_mutex r;
  r.lock(); r.lock(); r.unlock(); r.unlock();
  std::call_once(outer, [] { ++once_runs; std::call_once(inner, [] { ++once_runs; }); });
  std::call_once(outer, [] { ++once_runs; });
  std::printf("call_once runs=%d\n", once_runs);
  auto sp = std::make_shared<int>(7);
  auto copy = std::atomic_load(&sp);
  std::atomic_store(&sp, std::make_shared<int>(8));
  std::printf("shared_ptr atomic old=%d new=%d\n", *copy, *std::atomic_load(&sp));
  int v[5] = {1, 2, 3, 4, 5};
  std::random_shuffle(v, v + 5);
  std::sort(v, v + 5);
  std::printf("random_shuffle sorted=%d%d%d%d%d\n", v[0], v[1], v[2], v[3], v[4]);
  auto t0 = std::chrono::steady_clock::now();
  std::printf("steady_clock monotonic=%d\n", std::chrono::steady_clock::now() >= t0 ? 1 : 0);
  return 0;
}
