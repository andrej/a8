#include "util.h"

size_t line_length(const char *buf, size_t count)
{
	size_t i = 0;
	if(NULL == buf || 0 == count) {
		return 0;
	}
	for(; i < count && buf[i] != '\0' && buf[i] != '\n'; i++);
	if(i < count) {
		i++;
	}
	return i;
}

ssize_t next_int_line(const char *buf, size_t count, int *out)
{
	size_t line_n = 0;
	char num_buf[32]; // Enough to hold base-10 64-bit integer
	int num = 0;

	// Skip empty lines
	size_t skipped = 0;
	while((line_n = line_length(buf + skipped, count - skipped)) == 1) {
		skipped += line_n;
	}
	if(skipped >= count) {
		return -1;
	}

	// Parse integer
	if(line_n > 31) {
		return -1;
	}
	memcpy(num_buf, buf + skipped, line_n);
	num_buf[line_n] = '\0';
	if(0 != kstrtoint(buf + skipped, 10, &num)) {
		return 0;
	}
	*out = num;
	return skipped + line_n;
}
