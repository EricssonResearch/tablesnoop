#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib.h"

/* Simple dynamically resizing array
 * for netns items */
struct array *array_init(size_t capacity, size_t elem_size)
{
    struct array *array = calloc(1, sizeof(struct array));

    if (array) {
        array->elem_size = elem_size;
        array->data = calloc(capacity, elem_size);

        if (array->data) {
            array->size = 0;
            array->capacity = capacity;
        } else {
            free(array);
            array = NULL;
        }
    }

    return array;
}

bool array_add(struct array *array, void *value)
{
    if (array->size == array->capacity) {
        array->capacity *= 2;
        array->data = realloc(array->data, array->capacity * array->elem_size);

        if (array->data == NULL)
            return false;
    }

    void *dst = array->data + array->size * array->elem_size;
    memcpy(dst, value, array->elem_size);
    array->size += 1;
    return true;
}

const void *array_peek(const struct array *array, size_t index)
{
    if (array && array->size > index) {
        return array->data + index * array->elem_size;
    }

    return NULL;
}

size_t array_get_size(const struct array *array)
{
    return array->size;
}

void array_free(struct array *array)
{
    free(array->data);
    array->data = NULL;
    array->capacity = 0;
    array->size = 0;
}


long get_netns_cookie(void)
{
    int sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0) {
        perror("socket");
        return sk;
    }

    long cookie = -1;
    socklen_t sz = sizeof(cookie);

    if (getsockopt(sk, SOL_SOCKET, SO_NETNS_COOKIE, &cookie, &sz) != 0) {
        perror("getsockopt");
    }

    close(sk);

    return cookie;
}


long get_netns_fd(void)
{
    long netns_fd = open("/proc/self/ns/net", O_RDONLY);

    if (netns_fd < 0)
        perror("open");

    return netns_fd;
}
