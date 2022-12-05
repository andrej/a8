#ifndef SERIALIZATION_H
#define SERIALIZATION_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/**
 * The serializer supports serializing data into one contiguous buffer. It does
 * so according to the given `struct type`, which describes how the data is to
 * be interpreted.
 * 
 * A datum can be an immediate, a pointer, a buffer, or a descriptor. These
 * types are serialized as follows:
 * 
 * IMMEDIATE:
 *  left as-is and copied into the serialized buffer
 * 
 * POINTER:
 *  buffer[0 .. 7] = zeroed-out
 *  buffer[8 ..  ] = serialized dereferenced pointer according to pointer.type
 * 
 * BUFFER:
 *  buffer[0 .. length - 1] = contents of original buffer copied 1:1, but any
 *                            references are zeroed-out
 *  buffer[length .. length+M-1] = serialized first reference contained within
 *                                 buffer, where M is the number of bytes that
 *                                 serialization requires. the value inside the
 *                                 buffer at references[i].offset will be
 *                                 replaced with the deserialized value
 * buffer[length+M .. length+M+N-1] = ...
 */

enum type_kind {
	IMMEDIATE,
	POINTER,
	BUFFER,
	DESCRIPTOR
};

struct type;

struct immediate {
	size_t size;
};

struct pointer {
	struct type *type;
};

struct buffer_content {
	size_t offset;
	struct type *type;
};

struct buffer {
	size_t length;
	size_t n_references;
	struct buffer_content const *references;
};

struct descriptor {
	int fd;
};

struct type {
	enum type_kind kind;
	union {
		struct immediate immediate;
		struct pointer pointer;
		struct buffer buffer;
		struct descriptor descriptor;
	};
};

#define IMMEDIATE_TYPE(typ) {IMMEDIATE, .immediate = {sizeof(typ)}}
#define SIMPLE_BUFFER_TYPE(sz) {BUFFER, .buffer = {sz}}
#define POINTER_TYPE(pointee_typ) {POINTER, .pointer = {pointee_typ}}

size_t get_serialized_size(const char *buf, const struct type *type);

ssize_t serialize_into(const char *inp, const struct type *type, char *buf);

char *serialize(const char *inp, const struct type *type, size_t *len);

ssize_t deserialize_in_place(char *buf, const struct type *type, 
                             size_t *consumed);

#endif