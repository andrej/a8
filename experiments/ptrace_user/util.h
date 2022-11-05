#ifndef UTIL_H
#define UTIL_H

#define TRY(x) { if(0 != (x)) { \
	printf("Something went wrong at " #x "\n"); \
	return 1; \
}}

#endif
