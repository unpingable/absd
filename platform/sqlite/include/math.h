/* The libm surface SQLite uses: log and fabs (FTS5 ranking, defined in
 * absd-sqlite) and isnan (HAVE_ISNAN, a compiler builtin). */
double log(double);
double fabs(double);
#define isnan(x) __builtin_isnan(x)
