#ifndef __XALLOC_H
#define __XALLOC_H

#include <stdlib.h>

void *xalloc(size_t size);
char *xstrndup(const char *s, size_t n);
void *xrealloc(void *buffer, size_t size);

#endif  /* __XALLOC_H */
