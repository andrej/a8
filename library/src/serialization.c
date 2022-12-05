#include "serialization.h"

size_t get_serialized_size(const char *buf, const struct type *type)
{
	switch(type->kind) {
		case IMMEDIATE: {
			return type->immediate.size;
		}
		case POINTER: {
			if(*(void **)buf == NULL) {
				return sizeof(uint64_t);
			}
			return sizeof(uint64_t) + 
			       get_serialized_size(*(const char **)buf,
			                           type->pointer.type);
		}
		case BUFFER: {
			size_t n = type->buffer.length;
			for(int i = 0; i < type->buffer.n_references; i++) {
				const struct buffer_content *reference = 
					&type->buffer.references[i];
				n += get_serialized_size(
					buf + reference->offset,
					reference->type);
			}
			return n;
		}
		case DESCRIPTOR: {
			return sizeof(int32_t);
		}
	}
}

ssize_t serialize_into(const char *inp, const struct type *type, char *buf)
{
	switch(type->kind) {
		case IMMEDIATE:
		case DESCRIPTOR: 
		{
			memcpy(buf, inp, type->immediate.size);
			return type->immediate.size;
		}
		case POINTER: {
			size_t len = sizeof(uint64_t);
			if(*(void **)inp == NULL) {
				*(uint64_t *)buf = 0UL;
				return len;
			}
			*(uint64_t *)buf = ~0UL;
			len += serialize_into(*(char **)inp, 
			                      type->pointer.type,
			                      buf + sizeof(uint64_t));
			return len;
		}
		case BUFFER: {
			const struct buffer_content *reference;
			size_t len = 0;
			memcpy(buf, inp, type->buffer.length);
			len += type->buffer.length;
			for(int i = 0; i < type->buffer.n_references; i++) {
				size_t n = 0;
				reference = &type->buffer.references[i];
				n = serialize_into(inp + reference->offset,
					           reference->type,
					           buf + len);
				if(n < 0) {
					return -1;
				}
				len += n;
			}
			return len;
		}
	}
	return -1; /* unreachable */
}

char *serialize(const char *inp, const struct type *type, size_t *len)
{
	size_t n = get_serialized_size(inp, type);
	char *buf = calloc(n, 1);
	if(NULL == buf) {
		return NULL;
	}
	if(n != serialize_into(inp, type, buf)) {
		free(buf);
		return 0;
	}
	*len = n;
	return buf;
}

ssize_t deserialize_in_place(char *buf, const struct type *type, 
                             size_t *consumed)
{
	switch(type->kind) {
		case IMMEDIATE: 
		case DESCRIPTOR:
		{
			// Only works for long long immediates currently.
			// Would need to do some work here for smaller sizes.
			*consumed = type->immediate.size;
			return type->immediate.size;
		}
		case POINTER: {
			if(*(uint64_t *)buf == 0UL) {
				*consumed = sizeof(uint64_t);
				return sizeof(void *);
			}
			ssize_t s = 0;
			size_t rec_consumed = 0;
			s = deserialize_in_place(buf + sizeof(uint64_t), 
			                         type->pointer.type,
						 &rec_consumed);
			if(0 > s) {
				return s;
			}
			*(void **)buf = buf + sizeof(uint64_t);
			*consumed = sizeof(uint64_t) + rec_consumed;
			return sizeof(void *);
		}
		case BUFFER: {
			const struct buffer_content *reference;
			size_t offset = type->buffer.length;
			size_t total_consumed = type->buffer.length;
			for(int i = 0; i < type->buffer.n_references; i++) {
				size_t s = 0;
				size_t rec_consumed = 0;
				reference = &type->buffer.references[i];
				s = deserialize_in_place(buf + offset,
				                         reference->type,
							 &rec_consumed);
				if(0 > s) {
					return s;
				}
				/* Update the contents in the buffer with the
				   deserialized content (likely a pointer): */
				memcpy(buf + reference->offset, 
				       buf + offset,
				       s);
				offset += rec_consumed;
				total_consumed += rec_consumed;
			}
			*consumed = total_consumed;
			return type->buffer.length;
		}
	}
	return -1; /* unreachable*/
}
