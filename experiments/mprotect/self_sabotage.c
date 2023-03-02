/* Expected output of this program:

   `main` is located at 0x400xxx, on page 0x400000.
   Hello,
   Segmentation fault
   */
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>

#define PAGE_SIZE 4096

int main(int argc, char **argv)
{
	void * const this_page = (void *)
		((uint64_t)(&main) & ~(PAGE_SIZE - 1));
	printf("`main` is located at %p, on page %p.\n", &main, this_page);
	printf("Hello,\n");
	mprotect(this_page, PAGE_SIZE, PROT_READ);
	printf("World!\n");
	return 0;
}