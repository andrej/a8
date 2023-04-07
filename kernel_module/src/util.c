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
	size_t skipped = 0;
	char num_buf[32] = {}; // Enough to hold base-10 64-bit integer
	int num = 0;

	// Skip empty lines and whitespace
	for(; skipped < count && buf[skipped] != '\0' && isspace(buf[skipped]);
	    skipped++);
	if(skipped >= count || buf[skipped] == '\0') {
		// There was only whitespace remaining.
		return 0;
	}
	buf += skipped;
	// This never overflows because we just ensured count > skipped:
	count -= skipped;

	// Parse integer
	for(; line_n < count && buf[line_n] != '\0' && isdigit(buf[line_n]);
	    line_n++) {
		num_buf[line_n] = buf[line_n];
	}
	if(line_n == 0 || line_n > 31) {
		// First case: first character after whitespace was illegal
		// Second case: number is too large
		return -1;
	}
	num_buf[line_n] = '\0';
	if(0 != kstrtoint(num_buf, 10, &num)) {
		return -1;
	}
	*out = num;
	return skipped + line_n;
}

