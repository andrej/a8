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
				       type_size(reference->type));
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

ssize_t deserialize(void *buf, const struct type *type, void *dest, 
                    enum deserialize_approach approach)
{ 
	assert(approach == DESERIALIZE_OVERWRITE
	       || approach == DESERIALIZE_IN_PLACE && buf == dest);
	switch(type->kind) {
		case IGNORE:
		{
			/* Write 0 to deserialize_into. */
			if(NULL != dest) {
				*((uint32_t *)dest) = 0;
			}
			return sizeof(uint32_t);
		}
		case IMMEDIATE: 
		case DESCRIPTOR:
		{
			/* Copy sizeof(imm) from buf to deserialize_into. */
			if(NULL != dest && buf != dest) {
				// TODO handle endianness
				memcpy(dest, buf, type->immediate.size);
			}
			return type->immediate.size;
		}
		case POINTER: {
			/* Serialized:    <NULL/NON-NULL?> <SER. PTR DEST>
			   Deserialized:  <PTR TO +8>      <DESER. PTR DEST>
			                   \________________/
			   
			   For DESERIALIZE_IN_PLACE, pointer to buf + 8 is 
			   inserted. Pointer destination is recursively 
			   deserialized.  
			   
			   For DESERIALIZE_OVERWRITE, the pointer value at dest
			   is read and remains unmodified. The pointee is
			   deserialized recursively into the address at dest. */
			struct type *pointee = type->pointer.type;

			/* Set pointer to deserialized pointee. */
			void *recursive_dest = NULL;
			if(*(uint64_t *)buf != 0UL) {
				if(DESERIALIZE_IN_PLACE == approach) {
					recursive_dest = buf + sizeof(void *);
				} else if(DESERIALIZE_OVERWRITE == approach) {
					recursive_dest = *(void **)dest;
				}
			}
			if(NULL != dest) {
				*(void **)dest = recursive_dest;
			}

			/* Recursively deserialize pointee. */
			ssize_t s = 0;
			if(*(uint64_t *)buf != 0UL) {
				s = deserialize(buf + sizeof(uint64_t), pointee,
				                recursive_dest, approach);
				if(0 > s) {
					return s;
				}
			}
			return sizeof(uint64_t) + s;
		}
		case STRING: {
			/* Copy string into deserialize_into. */
			if(NULL != dest && buf != dest) {
				strcpy(dest, buf);
			}
			return strlen(buf) + 1;
		}
		case BUFFER: {
			/* Serialized:   <BUFFER> <SER. REF 1> <SER. REF 2> ...
			                   x  x
			                   |  |
			               refs redacted 

			   Deserialized: <BUFFER> <DESER. REF 1> ...
			                   x  x    |             |
			                   \__|____/             | 
			                      \__________________/
			   
			   For DESERIALIZE_IN_PLACE, buffer is left in-place. 
			   Pointers in buffer are updated to point to 
			   deserialized-in-place offsets in the buffer. 
			
			   For DESERIALIZE_OVERWRITE, buffer contents are
			   copied into `dest`. Pointer values present in the
			   buffer before deserialization are retained and not
			   overwritten -- recursive reference are deserialized
			   into the locations given there.  */
			
			/* Remember pointers present in `dest` buffer, because
			   we will use them to recursively deserialize 
			   references into those locations. */
			void *ptrs[type->buffer.n_references];
			if(approach == DESERIALIZE_OVERWRITE) {
				for(size_t i = 0; i < type->buffer.n_references; 
				    i++) {
					ptrs[i] = *(void **)(dest 
					  + type->buffer.references[i].offset);
				}
			}

			/* Deserialize buffer itself. */
			if(NULL != dest && buf != dest) {
				memcpy(dest, buf, type->buffer.length);
			}

			/* Recursively deserialize references. */
			size_t offset = type->buffer.length;
			for(int i = 0; i < type->buffer.n_references; i++) {
				const struct buffer_reference *reference = 
					&type->buffer.references[i];
				size_t s = 0;
				void *recursive_dest = NULL;
				if(approach == DESERIALIZE_IN_PLACE) {
					recursive_dest = buf + offset;
				} else if(approach == DESERIALIZE_OVERWRITE) {
					*(void **)(dest + reference->offset) =
						ptrs[i];
					recursive_dest = 
						dest + reference->offset;
				}
				s = deserialize(buf + offset, reference->type,
				                recursive_dest, approach);
				if(0 > s) {
					return s;
				}
				offset += s;
				/* Update pointers in buffer. Note that for
				   DESERIALIZE_OVERWRITE, the pointers in the 
				   buffer should remain the same as passed-in
				   in `dest`. */
				if(NULL != dest 
				   && DESERIALIZE_IN_PLACE == approach) {
					memcpy(dest + reference->offset, 
					       recursive_dest,
					       type_size(reference->type));
				}
			}
			return offset;
		}
	}
	return -1; /* unreachable*/
}

ssize_t deserialize_in_place(void *buf, struct type *type)
{
	return deserialize(buf, type, buf, DESERIALIZE_IN_PLACE);
}

ssize_t deserialize_overwrite(void *buf, struct type *type, void *dest)
{
	return deserialize(buf, type, dest, DESERIALIZE_OVERWRITE);
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
			append("DESCRIPTOR is ");
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

size_t type_size(const struct type *type)
{
	switch(type->kind) {
		case IGNORE:
			return sizeof(uint32_t);
		case DESCRIPTOR:
		case IMMEDIATE:
			return type->immediate.size;
		case POINTER:
			return sizeof(void *);
		case BUFFER:
			return type->buffer.length;
		case STRING:
			return 0; // FIXME
	}
}

size_t get_n_references(const void *buf, const struct type *type)
{
	switch(type->kind) {
		case IGNORE:
		case IMMEDIATE:
		case DESCRIPTOR:
		case STRING:
			return 0;
		case POINTER: {
			if(*(uint64_t *)buf != 0UL) {
				return 1;
			}
			return 0;
		}
		case BUFFER: {
			size_t n = type->buffer.n_references;
			struct buffer_reference *ref;
			for(size_t i = 0; i < n; i++) {
				ref = &type->buffer.references[i];
				n += get_n_references(
					buf + ref->offset,
					ref->type);
			}
			return n;
		}
	}
}
