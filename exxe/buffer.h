#ifndef __BUFFER_H
#define __BUFFER_H

struct buffer {
	char *buffer;
	size_t size;
	size_t start, end;
};

void *xalloc(size_t size);
char *xstrndup(const char *s, size_t n);
void *xrealloc(void *buffer, size_t size);

void reset_buffer(struct buffer *buffer);
void init_buffer(struct buffer *buffer);

static inline size_t buffer_available(struct buffer *buffer)
{
	return buffer->size - buffer->end;
}

static inline char *buffer_read_pos(struct buffer *buffer)
{
	return buffer->buffer + buffer->start;
}

static inline void buffer_advance_read(struct buffer *buffer, size_t size)
{
	buffer->start += size;
}

static inline char *buffer_write_pos(struct buffer *buffer)
{
	return buffer->buffer + buffer->end;
}

static inline void buffer_advance_write(struct buffer *buffer, size_t size)
{
	buffer->end += size;
}

static inline size_t buffer_size(struct buffer *buffer)
{
	return buffer->end - buffer->start;
}

void __grow_buffer(struct buffer *buffer, size_t size);

static inline void grow_buffer(struct buffer *buffer, size_t size)
{
	if (buffer_available(buffer) < size)
		__grow_buffer(buffer, size);
}

static inline void put_buffer(struct buffer *buffer, char c)
{
	if (buffer_available(buffer) < 1)
		__grow_buffer(buffer, 1);
	*buffer_write_pos(buffer) = c;
	buffer_advance_write(buffer, 1);
}

static inline int get_buffer(struct buffer *buffer)
{
	char c;

	if (buffer_size(buffer) == 0)
		return EOF;
	c = *buffer_read_pos(buffer);
	buffer_advance_read(buffer, 1);
	return (unsigned char)c;
}

int unget_buffer(struct buffer *buffer, int c);

void free_buffer(struct buffer *buffer);
char *steal_buffer(struct buffer *buffer);

extern struct buffer expanded_input;

#endif  /* __BUFFER_H */
