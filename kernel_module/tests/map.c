#include "test_suite/test.h"
#include "../include/map.h"

TEST(map_simple_add)
{
	int i = 0;
	struct char_to_short_map map_struct(char, short, 6);
	struct char_to_short_map a = {};
	ASSERT_EQ(a.size, 0);
	ASSERT_EQ(map_put(a, 4, 2), 0); // 4 --> 2
	i = map_get(a, 4);
	ASSERT_EQ(i, 0);
	ASSERT_EQ(a.values[i], 2);
	ASSERT_EQ(map_put(a, 3, 1), 0); // 3 --> 1
	i = map_get(a, 4);
	ASSERT_EQ(i, 0);
	ASSERT_EQ(a.values[i], 2);
	i = map_get(a, 3);
	ASSERT_EQ(i, 1);
	ASSERT_EQ(a.values[i], 1);
	return 0;
}

TEST(map_overfill)
{
	int i = 0;
	struct long_long_map map_struct(long, long, 13);
	struct long_long_map a = {};
	for(i = 0; i < 13; i++) {
		ASSERT_EQ(a.size, i);
		ASSERT_EQ(map_put(a, i, 10*i), 0);
	}
	ASSERT_EQ(a.size, 13);
	ASSERT_EQ(map_put(a, 13, 130), 1);
	ASSERT_EQ(a.size, 13);
	return 0;
}

TEST(map_del_fill_in_holes)
{
	int i = 0; 
	int k = 0;
	struct char_long_map map_struct(long, long, 13);
	struct char_long_map a = {};
	for(i = 0; i < 13; i++) {
		if(i > 0 && i % 2 == 0) {
			ASSERT_NEQ(k = map_get(a, i/2), -1);
			ASSERT_EQ(a.values[k], (i/2)*12);
			ASSERT_EQ(map_del(a, i/2), 0);
			ASSERT_EQ(map_get(a, i/2), -1);
		}
		ASSERT_EQ(map_put(a, i, 12*i), 0);
		ASSERT_NEQ(k = map_get(a, i), -1);
		ASSERT_EQ(a.values[k], i*12);
	}
	return 0;
}