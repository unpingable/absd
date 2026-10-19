/* The actual C-kit header retains V1; V2 is an explicit separate layout. */
#include <absd/runtime.h>
#define OFFSET(type, member, value) _Static_assert(offsetof(struct type, member) == value, #type "." #member)
_Static_assert(sizeof(struct absd_raw_attr) == 40, "V1 size");
_Static_assert(sizeof(struct absd_raw_attr_v2) == 48, "V2 size");
OFFSET(absd_raw_attr, kind, 0);
OFFSET(absd_raw_attr, readonly, 4);
OFFSET(absd_raw_attr, size, 8);
OFFSET(absd_raw_attr, filesystem, 16);
OFFSET(absd_raw_attr, serial, 24);
OFFSET(absd_raw_attr, links, 32);
OFFSET(absd_raw_attr_v2, kind, 0);
OFFSET(absd_raw_attr_v2, readonly, 4);
OFFSET(absd_raw_attr_v2, size, 8);
OFFSET(absd_raw_attr_v2, filesystem, 16);
OFFSET(absd_raw_attr_v2, serial, 24);
OFFSET(absd_raw_attr_v2, links, 32);
OFFSET(absd_raw_attr_v2, mtime, 40);
