/* C allocation over the runtime's sized allocator (spec 3.2, A2). Every
   block carries {size, align} in the 16 bytes before the pointer; the
   block base is pointer - slot, slot = max(align, 16). One allocator: the
   runtime's. Picolibc's malloc is not built; sbrk is refused (clock.c). */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "absd/runtime.h"

#define ABSD_HEAP_MIN_ALIGN 16u

struct absd_heap_header { size_t size; size_t align; };

static size_t slot_for(size_t align) { return align > ABSD_HEAP_MIN_ALIGN ? align : ABSD_HEAP_MIN_ALIGN; }

static void *heap_alloc(size_t size, size_t align) {
    if (align < ABSD_HEAP_MIN_ALIGN) align = ABSD_HEAP_MIN_ALIGN;
    size_t slot = slot_for(align), total;
    if (__builtin_add_overflow(size, slot, &total)) { errno = ENOMEM; return NULL; }
    unsigned char *base = __absd_std_alloc(total, align);
    if (base == NULL) { errno = ENOMEM; return NULL; }
    unsigned char *user = base + slot;
    struct absd_heap_header *header = (struct absd_heap_header *)(user - sizeof *header);
    header->size = size;
    header->align = align;
    return user;
}

static struct absd_heap_header *header_of(void *pointer) {
    return (struct absd_heap_header *)((unsigned char *)pointer - sizeof(struct absd_heap_header));
}

void *malloc(size_t size) { return heap_alloc(size, ABSD_HEAP_MIN_ALIGN); }

void free(void *pointer) {
    if (pointer == NULL) return;
    struct absd_heap_header *header = header_of(pointer);
    size_t slot = slot_for(header->align);
    __absd_std_dealloc((unsigned char *)pointer - slot, header->size + slot, header->align);
}

void *calloc(size_t count, size_t size) {
    size_t total;
    if (__builtin_mul_overflow(count, size, &total)) { errno = ENOMEM; return NULL; }
    void *pointer = malloc(total);
    if (pointer != NULL) memset(pointer, 0, total);
    return pointer;
}

void *realloc(void *pointer, size_t size) {
    if (pointer == NULL) return malloc(size);
    struct absd_heap_header *header = header_of(pointer);
    void *grown = heap_alloc(size, header->align);
    if (grown == NULL) return NULL;            /* errno ENOMEM; the original stays valid */
    memcpy(grown, pointer, header->size < size ? header->size : size);
    free(pointer);
    return grown;
}

void *aligned_alloc(size_t align, size_t size) {
    if (align == 0 || (align & (align - 1)) != 0) { errno = EINVAL; return NULL; }
    return heap_alloc(size, align);
}

int posix_memalign(void **out, size_t align, size_t size) {
    if (align == 0 || (align & (align - 1)) != 0 || align % sizeof(void *) != 0) return EINVAL;
    void *pointer = heap_alloc(size, align);
    if (pointer == NULL) return ENOMEM;
    *out = pointer;
    return 0;
}

size_t malloc_usable_size(void *pointer) { return pointer == NULL ? 0 : header_of(pointer)->size; }
