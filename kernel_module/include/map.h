/* This is all kept as macros so it works for generic types.
   Intended for very small maps where a linear search is acceptable.
   Does not protect against adding the same key multiple times. The first
   occurence will be returned for a get. */

#define map_struct(k_type, v_type, cap) \
	{ \
		unsigned long size; \
		unsigned char occupied[(cap + 7) / 8]; \
		k_type keys[cap]; \
		v_type values[cap]; \
	} 

#define map_capacity(map) \
	(sizeof((map).keys)/sizeof((map).keys[0]))

#define map_put(map, k, v) ({ \
	int __ret = 0; \
	int __i = 0; \
	if(map_capacity(map) > (map).size) { \
		for(__i = 0; __i < map_capacity(map); \
		    __i++) {\
			if(!(((map).occupied[__i/8] >> (__i%8)) & 1U)) { \
				break; \
			} \
		} \
		if(__i < map_capacity(map)) { \
			(map).occupied[__i/8] |= 1U << (__i%8); \
			(map).size++; \
			(map).keys[__i] = k; \
			(map).values[__i] = v; \
			__ret = 0; \
		} else { \
			__ret = 2; \
		} \
	} else { \
		__ret = 1; \
	} \
	__ret; \
})

/* return index in map; -1 if not found */
#define map_get(map, k) ({ \
	int __i = 0; \
	for(; __i < map_capacity(map); __i++) { \
		if(((map).occupied[__i/8]>>(__i%8)) & 1U) { \
			if((map).keys[__i] == (k)) { \
				break; \
			} \
		} \
	} \
	if(__i == map_capacity(map)) { \
		__i = -1; \
	} \
	__i; \
})

#define map_del_idx(map, __i) ({ \
	int ret = 0; \
	if(0 <= __i && __i < map_capacity(map)) { \
		(map).occupied[__i/8] &= ~(1<<(__i%8)); \
		(map).size--; \
		ret = 0; \
	} else { \
		ret = 1; \
	} \
	ret; \
})

#define map_del(map, k) ({ \
	int __ret = 0; \
	int __i = map_get(map, k); \
	if(-1 != __i) { \
		map_del_idx(map, __i); \
		__ret = 0; \
	} else { \
		__ret = 1; \
	} \
	__ret; \
})
