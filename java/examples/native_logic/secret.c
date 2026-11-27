/* Secret algorithm compiled into a native shared library. Returns a value
   the payload needs, so it cannot be bypassed by ignoring a boolean. Logic
   never ships as Java bytecode -- the `native` method that calls this has
   no Code attribute at all, by the class file spec. */
#include <stdint.h>

int64_t secret_transform(int64_t x) {
    int64_t r = (x * 2654435761LL) ^ 0x5A17;
    r = (r % 1000000 + 1000000) % 1000000 + 42;
    return r;
}
