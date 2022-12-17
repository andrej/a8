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
 * STRING:
 *  like BUFFER but length is determined by null-terminator
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
 * 
 */

enum type_kind {
	IGNORE,
	IMMEDIATE,
	POINTER,
	BUFFER,
	STRING,
	DESCRIPTOR
};

struct type;


struct immediate {
	size_t size;
};

struct pointer {
	struct type *type;
};

struct string {};

struct buffer_reference {
	size_t offset;
	struct type *type;
};

struct buffer {
	size_t length;
	size_t n_references;
	struct buffer_reference * references;
};

struct descriptor {
	int fd;
};

struct type {
	enum type_kind kind;
	union {
		struct immediate immediate;
		struct pointer pointer;
		struct string string;
		struct buffer buffer;
		struct descriptor descriptor;
	};
};

#define IMMEDIATE_TYPE(typ) {IMMEDIATE, .immediate = {sizeof(typ)}}
#define SIMPLE_BUFFER_TYPE(sz) {BUFFER, .buffer = {sz}}
#define POINTER_TYPE(pointee_typ) {POINTER, .pointer = {pointee_typ}}

size_t get_serialized_size(const void *buf, const struct type *type);

/**
 * Serialize into the given buffer. Requires that buffer has the approrpiate
 * size as returned by get_serialized_size().
 * 
 * Returns the total number of bytes written to the buffer.
 */
ssize_t serialize_into(const void *inp, const struct type *type, void *buf);

char *serialize(const void *inp, const struct type *type, size_t *len);

/**
 * Deserialize buffer in place s.t. a pointer to this buffer can be
 * interpreted as a pointer to the correct data type.
 * 
 * Sets the number of bytes in buffer consumed to the integer pointed to by
 * consumed. Returns the number of bytes consumed at the top-level recursive
 * call, which is the same for all data types as consumed except for buffers.
 * For buffers, it returns the size of the main buffer, without the length of
 * any deserialized other buffers referenced from within the buffer through 
 * pointers. However, those buffers are also deserialized and pointer addresses
 * appropriately updated -- the total number of bytes consumed for this is
 * stored in consumed.
 */
ssize_t deserialize_in_place(void *buf, const struct type *type, 
                             size_t *consumed);

/**
 * Return string in human-readable format that represents the data `inp`
 * in the format described by `type`.
 */
size_t log_str_of(const void *inp, const struct type *type, 
                  char *buf, size_t max_len);
#endif