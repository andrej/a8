#ifndef LIST_H
#define LIST_H

/* Simple macro abstractons for a variable-length list with a fixed capacity. */
#define list_struct_def(item_type, capacity) \
	{ \
		uint64_t occupied[((capacity) + 63) / 64]; \
		item_type items[capacity]; \
	}

#define list_capacity(l) \
	(sizeof((l).items) / sizeof((l).items[0]))

#define list_item_is_occupied(l, i) \
	(((l).occupied[(i)/64] >> ((i)%64)) & 1)

#define list_for_each(l, i) \
	for(i = 0; i < list_capacity(l); i++) \
	

/* Add itm to the lowest-index free slot in the list, and return that index,
   if any. If list is full, return -1. */
#define list_put(l, itm) \
	({ \
		size_t idx = list_get_next_free_i(l); \
		if(idx == list_capacity(l)) { \
			idx = -1; \
		} else { \
			list_put_at(l, itm, idx); \
		} \
		idx; \
	})

#define list_get_next_free_i(l) \
	({ \
		size_t idx = 0; \
		while(idx < list_capacity(l) && list_item_is_occupied(l, idx)) \
		{ \
			idx++; \
		} \
		idx; \
	})

#define list_put_at(l, itm, idx) \
	({ \
		(l).items[(idx)] = (itm); \
		(l).occupied[(idx)/64] |= 1UL << ((idx)%64); \
	})

/* Retrieve pointer to item at index, or NULL if nothing is stored at that 
   index */
#define list_get_i(l, i) \
	({ \
		typeof((l).items[0]) *ret = NULL; \
		if(0 <= (i) && (i) < list_capacity(l) \
		   && ((l).occupied[(i)/64] >> ((i)%64)) & 1) { \
		   	ret = &(l).items[i]; \
		} \
		ret; \
	}) \

/* Remove an item from the list, freeing its spot. */
#define list_del_i(l, i) \
	({ \
		int ret = 0; \
		if(NULL == list_get_i(l, (i))) { \
			ret = -1; \
		} else { \
			(l).occupied[(i)/64] &= ~ (1UL << ((i)%64)); \
		} \
		ret; \
	})

#endif