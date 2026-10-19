/* Stage 3 probe (tcc/cases.tsv `probe`): compiled by /bin/tcc in the guest
   and by the host's tcc for Linux; the output must be equal. One feature
   per line, each with a checksum of its results; no asm, no %Lf, no input,
   nothing that depends on time, addresses or the environment. */
#include <alloca.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static unsigned long fnv(const void *data, size_t n, unsigned long h) {
    const unsigned char *p = data;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ul; }
    return h;
}

/* varargs: a format of i (int), d (double), s (char *) */
static double take(const char *fmt, ...) {
    va_list ap;
    double sum = 0;
    unsigned long h = 14695981039346656037ul;
    va_start(ap, fmt);
    for (const char *f = fmt; *f; f++) {
        if (*f == 'i') { int v = va_arg(ap, int); sum += v; h = fnv(&v, sizeof v, h); }
        else if (*f == 'd') { double v = va_arg(ap, double); sum += v; }
        else if (*f == 's') { const char *s = va_arg(ap, const char *); sum += (double)strlen(s); h = fnv(s, strlen(s), h); }
    }
    va_end(ap);
    printf("varargs %s sum=%.6f h=%016lx\n", fmt, sum, h);
    return sum;
}

static unsigned long with_alloca(int n) {
    unsigned char *buf = alloca((size_t)n);
    for (int i = 0; i < n; i++) buf[i] = (unsigned char)(i * 7 + 3);
    return fnv(buf, (size_t)n, 14695981039346656037ul);
}

static int dense(int k) {
    switch (k) {
    case 0: return 11; case 1: return 23; case 2: return 37; case 3: return 41;
    case 4: return 53; case 5: return 67; case 6: return 71; case 7: return 89;
    case 8: return 97; case 9: return 101; case 10: return 113; case 11: return 127;
    case 12: return 131; case 13: return 149; case 14: return 151; case 15: return 163;
    default: return -1;
    }
}

static int sparse(long k) {
    switch (k) {
    case -70000: return 1; case -7: return 2; case 1: return 3; case 100: return 4;
    case 1000: return 5; case 65536: return 6; case 1000000: return 7; case 2147483647: return 8;
    default: return 0;
    }
}

static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }
static int mul(int a, int b) { return a * b; }
static int quo(int a, int b) { return b ? a / b : 0; }

/* static initialisers that need relocations: pointers to data, to strings, to functions */
static int cells[4] = { 5, 10, 15, 20 };
static int *const cellp[] = { &cells[3], &cells[0], &cells[2], &cells[1] };
static const char *const words[] = { "alpha", "beta", "gamma", "delta", "epsilon" };
static struct op { const char *name; int (*fn)(int, int); } const ops[] = {
    { "add", add }, { "sub", sub }, { "mul", mul }, { "quo", quo },
};
static const struct op *const last_op = &ops[3];

#define S16 "0123456789abcdef"
#define S64 S16 S16 S16 S16
#define S256 S64 S64 S64 S64
#define S1K S256 S256 S256 S256
static const char big[] = S1K S1K S1K S1K S1K;   /* 5 KiB, one literal */

int main(void) {
    double v = take("idsids", 7, 2.5, "probe", -3, 0.125, "tinycc");
    printf("varargs total=%.6f\n", v);
    printf("alloca 1000 h=%016lx 5000 h=%016lx\n", with_alloca(1000), with_alloca(5000));
    unsigned long hd = 14695981039346656037ul;
    int sd = 0;
    for (int k = -2; k < 20; k++) { int r = dense(k); sd += r; hd = fnv(&r, sizeof r, hd); }
    printf("switch dense sum=%d h=%016lx\n", sd, hd);
    static const long keys[] = { -70000, -7, 0, 1, 2, 100, 999, 1000, 65536, 65537, 1000000, 2147483647, -1 };
    int ss = 0;
    unsigned long hs = 14695981039346656037ul;
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) { int r = sparse(keys[i]); ss = ss * 3 + r; hs = fnv(&r, sizeof r, hs); }
    printf("switch sparse acc=%d h=%016lx\n", ss, hs);
    int acc = 1000;
    for (size_t i = 0; i < sizeof ops / sizeof ops[0]; i++) {
        acc = ops[i].fn(acc, (int)i + 3);
        printf("fnptr %s -> %d\n", ops[i].name, acc);
    }
    printf("fnptr last=%s(84,4)=%d\n", last_op->name, last_op->fn(84, 4));
    int cs = 0;
    for (size_t i = 0; i < 4; i++) cs = cs * 31 + *cellp[i];
    printf("static cells=%d words=%s,%s,%s,%s,%s\n", cs, words[0], words[1], words[2], words[3], words[4]);
    printf("literal bytes=%zu strlen=%zu h=%016lx tail=%s\n", sizeof big, strlen(big),
           fnv(big, sizeof big - 1, 14695981039346656037ul), big + sizeof big - 17);
    return 0;
}
