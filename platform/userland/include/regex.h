/* Build adaptation for the base userland (userland/README.md, "Build
   adaptations"); not a change to any sbase source. Picolibc 1.8.12's
   <regex.h> declares regex_t with a size_t member but includes <stddef.h>
   under __need_ptrdiff_t only (regex.h:41-49), so a source that includes
   <regex.h> before anything that defines size_t (sbase grep.c, sed.c) does
   not compile. This wrapper, first on the userland include path, defines
   size_t and then includes the kit's own header unchanged. */
#include <stddef.h>
#include_next <regex.h>
