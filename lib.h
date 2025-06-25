#include <stdbool.h>
#include <stdlib.h>

struct array {
    void *data;
    unsigned capacity;
    unsigned size;
    unsigned elem_size;
};

/* Simple dynamically resizing generic array. */
struct array *array_init(size_t capacity, size_t elem_size);
bool array_add(struct array *array, void *value);
const void *array_peek(const struct array *array, size_t index);
size_t array_get_size(const struct array *array);
void array_free(struct array *array);

/* Return the netns cookie value of the current namespace
 * on success and -1 on failure.
 * Note: can be used together with setns. */
long get_netns_cookie(void);

/* Return the netns file descriptor of the current net namespace
 * on success and -1 on failure.
 * Note: can be used together with setns.
 * Note: file descriptor should be closed by the caller*/
long get_netns_fd(void);
