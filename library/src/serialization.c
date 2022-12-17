#include <stdio.h>
#include <assert.h>
#include "serialization.h"

size_t get_serialized_size(const void *buf, const struct type *type)
{
	switch(type->kind) {
		case IGNORE: {
			return sizeof(uint32_t);
		}
		case IMMEDIATE: {
			return type->immediate.size;
		}
		case POINTER: {
			if(*(void **)buf == NULL) {
				return sizeof(uint64_t);
			}
			return sizeof(uint64_t) + 
			       get_serialized_size(*(const void **)buf,
			                           type->pointer.type);
		}
		case STRING: {
			return strlen(buf) + 1;
		}
		case BUFFER: {
			size_t n = type->buffer.length;
			for(int i = 0; i < type->buffer.n_references; i++) {
				const struct buffer_reference *reference = 
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

ssize_t serialize_into(const void *inp, const struct type *type, void *buf)
{
	switch(type->kind) {
		case IGNORE: {
			*((uint32_t *)buf) = 0;
			return sizeof(uint32_t);
		}
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
		case STRING: {
			size_t len = strlen(inp);
			strncpy(buf, inp, len);
			return len + 1;
		}
		case BUFFER: {
			const struct buffer_reference *reference;
			size_t len = 0;
			memcpy(buf, inp, type->buffer.length);
			len += type->buffer.length;
			for(int i = 0; i < type->buffer.n_references; i++) {
				size_t n = 0;
				reference = &type->buffer.references[i];
				n = serialize_into(buf + reference->offset,
					           reference->type,
					           buf + len);
				memset(buf + reference->offset, 0,
				       sizeof(void *));
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

char *serialize(const void *inp, const struct type *type, size_t *len)
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

ssize_t deserialize_in_place(void *buf, const struct type *type, 
                             size_t *consumed)
{
	switch(type->kind) {
		case IGNORE:
		{
			*consumed = sizeof(uint32_t);
			*((uint32_t *)buf) = 0;
			return sizeof(uint32_t);
		}
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
		case STRING: {
			// Nothing to be done.
			*consumed = strlen(buf) + 1;
			return *consumed;
		}
		case BUFFER: {
			const struct buffer_reference *reference;
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

static size_t write_printable_bytes(const char *inp, size_t inp_len,
                                    char *buf, size_t max_len) {
	size_t written = 0;
	for(size_t i = 0; i < inp_len && written < max_len-1; i++) {
		if(32 <= inp[i] && inp[i] <= 127) {
			buf[written] = inp[i];
			written++;
		} else {
			if(written + 4 < max_len) {
				written += 
				sprintf(buf + written, "\\%hhx", inp[i]);
			} else {
				break;
			}
		}
	}
	buf[written] = '\0';
	return written;
}

size_t log_str_of(const void *inp, const struct type *type, 
                  char *buf, size_t max_len)
{
	#define append(...) { \
		size_t len = 0; \
		if(offset < max_len - 1) { \
			len = snprintf(buf + offset, max_len - offset, \
			               __VA_ARGS__); \
			if(len >= max_len - offset) { \
				offset = max_len; \
			} else { \
				offset += len; \
			} \
		} \
	}
	size_t offset = 0;
	switch(type->kind) {
		case IGNORE:
			append("IGNORE");
			break;
		case DESCRIPTOR: {
			append("DESCRIPTOR");
			// fall-through
		}
		case IMMEDIATE: {
			long long v = 0;
			// assumes little-endianness:
			memcpy(&v, inp, type->immediate.size);
			append("IMMEDIATE %lld", v);
			break;
		}
		case POINTER: {
			append("POINTER to ");
			if(offset >= max_len - 1) {
				break;
			}
			offset += log_str_of(*(const char **)inp, 
			                     type->pointer.type,
			                     buf + offset, max_len - offset);
			break;
		}
		case STRING: {
			append("STRING \"%s\"", (const char *)inp);
			break;
		}
		case BUFFER: {
			size_t printed = 0;
			struct buffer_reference *reference = NULL;
			append("BUFFER [");
			for(int i = 0; i < type->buffer.n_references; i++) {
				reference = &type->buffer.references[i];
				if(offset >= max_len - 1) {
					break;
				}
				offset += write_printable_bytes(
						inp + printed,
						reference->offset - printed,
						buf + offset, max_len - offset);
				printed = reference->offset + sizeof(void *);
				append("<ADDR OF REF %d>", i);
			}
			if(offset >= max_len - 1) {
				break;
			}
			offset += write_printable_bytes(inp + printed, 
						type->buffer.length - printed,
						buf + offset, max_len - offset);
			append("]");

			if(0 < type->buffer.n_references) {
				append(" with");
			}
			for(int i = 0; i < type->buffer.n_references; i++) {
				reference = &type->buffer.references[i];
				append(" <REF %d: ", i);
				if(offset >= max_len - 1) {
					break;
				}
				offset += log_str_of(inp + reference->offset, 
				                reference->type,
						buf + offset, max_len - offset);
				append(">");
			}
			break;
		}
	}
	if(offset + 1 < max_len) {
		buf[offset + 1] = '\0';
	} else {
		buf[max_len - 1] = '\0';
	}
	return offset;
	#undef append
}
