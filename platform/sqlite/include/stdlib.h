/* Heap and sort functions SQLite links against; defined in absd-sqlite. */
#include <stddef.h>
void *malloc(size_t);
void free(void *);
void *realloc(void *, size_t);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
