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
 *  buffer[0 .. 7] = zeroed-out if pointer is null, otherwise all 1s
 *  buffer[8 ..  ] = recursively serialized dereferenced pointer according to 
 *                   pointer.type
 * 
 * STRING:
 *  like BUFFER but length is determined by null-terminator and no references
 * 
 * BUFFER:
 *  buffer[0 .. 7] = original buffer length
 *  buffer[8 .. 8+length-1] = contents of original buffer copied 1:1, but any
 *                            references contained in buffer are zeroed-out
 *  buffer[8+length .. 8+length+M-1] = serialized first reference contained 
 *                                 within buffer, where M is the number of bytes 
 *                                 that serialization requires. the value inside 
 *                                 the buffer at references[i].offset will be
 *                                 replaced with the deserialized value
 * buffer[8+length+M .. 8+length+M+N-1] = ...
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
	int flags;
	union {
		struct immediate immediate;
		struct pointer pointer;
		struct string string;
		struct buffer buffer;
		struct descriptor descriptor;
	};
};

enum deserialize_approach {
	DESERIALIZE_IN_PLACE,
	DESERIALIZE_OVERWRITE
};

#define IGNORE_TYPE() (struct type){IGNORE, .immediate = {sizeof(long)}}
#define IMMEDIATE_TYPE(typ) (struct type){IMMEDIATE, .immediate = {sizeof(typ)}}
#define POINTER_TYPE(pointee_typ) (struct type)\
	{POINTER, .pointer = {pointee_typ}}
#define BUFFER_TYPE(...) (struct type){BUFFER, .buffer = {__VA_ARGS__}}
#define STRING_TYPE() (struct type){STRING}
#define DESCRIPTOR_TYPE() (struct type){DESCRIPTOR, .immediate = {sizeof(int)}}

size_t get_serialized_size(const void *buf, const struct type *type);

/**
 * Serialize into the given buffer. Requires that buffer has the approrpiate
 * size as returned by get_serialized_size().
 * 
 * Returns the total number of bytes written to the buffer.
 */
ssize_t serialize_into(const void *inp, const struct type *type, void *buf);

char *serialize(const void *inp, const struct type *type, size_t *len);

ssize_t deserialize(void *buf, const struct type *type, void *dest,
                    enum deserialize_approach approach);

/**
 * Deserialize buffer in place s.t. a pointer to this buffer can be
 * interpreted as a pointer to the correct data type.
 * 
 * Returns the number of bytes in the input buffer consumed.
 */
ssize_t deserialize_in_place(void *buf, struct type *type);

/**
 * Deserialize the buffer `buf` to overwrite the value at `dest`. Any pointers
 * in `dest` are left as-is and recursively followed and deserialized into.
 * For example, if the serialized data type is a buffer, then buffer contents
 * are copied to `dest`, except for any pointers references (according to
 * data type) inside the buffer. The references serialized in `buf` are then
 * deserialized to the destinations pointed to at those offsets in the `dest`
 * buffer.
*/
ssize_t deserialize_overwrite(void *buf, struct type *type, void *dest);

/**
 * Return string in human-readable format that represents the data `inp`
 * in the format described by `type`.
 */
size_t log_str_of(const void *inp, const struct type *type, 
                  char *buf, size_t max_len);

/**
 * Return size taken up by a type, excluding any references.
 */
size_t type_size(const struct type *type);

#endif