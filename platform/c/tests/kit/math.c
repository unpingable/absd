#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(void) {
    printf("%.6f %.6f %.6f %.6f\n", sqrt(2.0), sin(1.0), exp(1.0), log(10.0));
    printf("%.3e %g %d\n", pow(2.0, 0.5), fabs(-3.25), (int)floor(-2.5));
    printf("strtod=%.17g atoi=%d\n", strtod("3.14159265358979", NULL), atoi("-42"));
    printf("isnan=%d isinf=%d\n", isnan(NAN), isinf(INFINITY));
    time_t now = time(NULL); printf("time %s\n", now == (time_t)-1 ? "refused" : "available");
    clock_t c = clock();   /* ruling R12: scaled to CLOCKS_PER_SEC; within a day of boot (ABSD) or of process start (Linux) */
    printf("clock_ok=%d\n", c != (clock_t)-1 && (unsigned long long)c < 24ull * 3600ull * (unsigned long long)CLOCKS_PER_SEC);
    return 0;
}
