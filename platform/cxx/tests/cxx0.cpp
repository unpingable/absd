// C++0 probe (cxx/README.md): the bounded C++ runtime on ABSD. Classes with
// virtual calls, templates, a global object with a non-trivial constructor
// and destructor (static init, then __cxa_atexit at exit), a function-local
// static (the no-threads guard), operator new/delete including aligned new,
// std::vector, std::string, std::unique_ptr, std::sort and std::map, built
// -fno-exceptions -fno-rtti. Output is printf only and must be byte-equal
// to the Linux build of the same source (cxx/tests/cxx0.expected). Nothing
// printed depends on the library's growth policy or object layout.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace {

int events = 0;

struct Global {
    int value;
    Global() : value(41) { std::printf("global ctor value=%d\n", value); ++events; }
    ~Global() {
        // Runs from exit() after main returns, through __cxa_atexit.
        std::printf("global dtor value=%d events=%d\n", value, events);
        std::fflush(stdout);
    }
};
Global global;

struct Shape {
    virtual ~Shape() = default;
    virtual long area() const = 0;
    virtual const char *name() const { return "shape"; }
};

struct Rect : Shape {
    long w, h;
    Rect(long w_, long h_) : w(w_), h(h_) {}
    long area() const override { return w * h; }
    const char *name() const override { return "rect"; }
};

struct Square final : Rect {
    explicit Square(long s) : Rect(s, s) {}
    const char *name() const override { return "square"; }
};

struct Tri : Shape {
    long b, h;
    Tri(long b_, long h_) : b(b_), h(h_) {}
    long area() const override { return b * h / 2; }
};

template <typename T, std::size_t N>
struct Ring {
    T items[N] = {};
    std::size_t head = 0, count = 0;
    void push(const T &v) {
        items[(head + count) % N] = v;
        if (count < N) ++count; else head = (head + 1) % N;
    }
    template <typename F>
    T fold(T init, F f) const {
        for (std::size_t i = 0; i < count; ++i) init = f(init, items[(head + i) % N]);
        return init;
    }
};

template <typename T>
T square_sum(const std::vector<T> &v) {
    T s{};
    for (const T &x : v) s += x * x;
    return s;
}

struct alignas(64) Wide {
    unsigned char bytes[200];
};

struct Counted {
    static int live, made;
    int id;
    explicit Counted(int i) : id(i) { ++live; ++made; }
    ~Counted() { --live; }
};
int Counted::live = 0, Counted::made = 0;

int &local_static() {
    static int value = [] { ++events; std::printf("local static init\n"); return 7; }();
    return value;
}

unsigned long checksum(const std::string &s) {
    unsigned long h = 5381;
    for (unsigned char c : s) h = h * 33 + c;
    return h;
}

}  // namespace

int main() {
    std::printf("C++0 probe start global=%d\n", global.value);

    std::vector<std::unique_ptr<Shape>> shapes;
    shapes.push_back(std::make_unique<Rect>(3, 4));
    shapes.push_back(std::make_unique<Square>(5));
    shapes.push_back(std::make_unique<Tri>(6, 7));
    long total = 0;
    for (const auto &s : shapes) {
        std::printf("shape %s area=%ld\n", s->name(), s->area());
        total += s->area();
    }
    std::printf("shapes=%zu total=%ld\n", shapes.size(), total);

    Ring<int, 4> ring;
    for (int i = 1; i <= 6; ++i) ring.push(i * 10);
    std::printf("ring count=%zu sum=%d max=%d\n", ring.count,
                ring.fold(0, [](int a, int b) { return a + b; }),
                ring.fold(0, [](int a, int b) { return std::max(a, b); }));

    std::vector<long> v;
    for (long i = 0; i < 1000; ++i) v.push_back((i * 7919) % 1009);
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    std::printf("vector unique=%zu front=%ld back=%ld squares=%ld\n", v.size(), v.front(), v.back(),
                square_sum(v));

    std::string s = "absd";
    for (int i = 0; i < 5; ++i) s += "-" + std::to_string(i * i);
    std::string big(5000, 'x');
    big.replace(10, 3, "C++0");
    std::printf("string %s len=%zu find=%zu big=%zu sum=%lu\n", s.c_str(), s.size(), s.find("-16"),
                big.size(), checksum(big));

    std::map<std::string, int> words;
    const char *text[] = {"pear", "fig", "pear", "apple", "fig", "pear"};
    for (const char *w : text) ++words[w];
    for (const auto &kv : words) std::printf("word %s=%d\n", kv.first.c_str(), kv.second);

    int *ints = new int[256];
    for (int i = 0; i < 256; ++i) ints[i] = i;
    long isum = 0;
    for (int i = 0; i < 256; ++i) isum += ints[i];
    delete[] ints;
    std::printf("new[] sum=%ld\n", isum);

    Wide *w = new Wide;
    std::memset(w->bytes, 0xab, sizeof w->bytes);
    std::printf("aligned new align64=%d byte=%d\n", (int)(reinterpret_cast<std::uintptr_t>(w) % 64 == 0),
                w->bytes[199]);
    delete w;
    Wide *ws = new Wide[3];
    std::printf("aligned new[] align64=%d\n", (int)(reinterpret_cast<std::uintptr_t>(ws) % 64 == 0));
    delete[] ws;

    void *raw = ::operator new(100000, std::nothrow);
    std::printf("nothrow new ok=%d\n", (int)(raw != nullptr));
    ::operator delete(raw);

    {
        std::vector<Counted *> cs;
        for (int i = 0; i < 50; ++i) cs.push_back(new Counted(i));
        std::printf("counted live=%d\n", Counted::live);
        for (Counted *c : cs) delete c;
    }
    std::printf("counted live=%d made=%d\n", Counted::live, Counted::made);

    local_static() += 1;
    local_static() += 1;
    std::printf("local static value=%d events=%d\n", local_static(), events);

    auto shared = std::make_shared<std::pair<int, std::string>>(3, "three");
    std::shared_ptr<std::pair<int, std::string>> alias = shared;
    std::printf("shared use=%ld second=%s\n", alias.use_count(), alias->second.c_str());

    std::printf("C++0 probe end\n");
    return 0;
}
