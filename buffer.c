#include "xalloc.h"
#include "buffer.h"

void reset_buffer(struct buffer *buffer)
{
	buffer->start = buffer->end = 0;
}

void init_buffer(struct buffer *buffer)
{
	buffer->buffer = NULL;
	buffer->size = 0;
	reset_buffer(buffer);
}

void __grow_buffer(struct buffer *buffer, size_t size)
{
	const size_t grow_chunk = 1 << 12, slow_growth_limit = 1 << 20;
	size_t new_size = buffer->size;

	if (size < grow_chunk)
		size = grow_chunk;
	if (new_size && size < slow_growth_limit) {
		while (new_size - buffer->end < size)
			new_size <<= 1;
	} else
		new_size += size;
	buffer->buffer = xrealloc(buffer->buffer, new_size);
	buffer->size = new_size;
}

void free_buffer(struct buffer *buffer)
{
	free(buffer->buffer);
}

char *steal_buffer(struct buffer *buffer)
{
	char *b;

	b = xrealloc(buffer->buffer, buffer_size(buffer));
	init_buffer(buffer);
	return b;
}
