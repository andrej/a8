/* The dynamic loader loads sections into segments. There is one executable
   segment that will contain the .text section. 

   We control access flags at the segment level using mprotect. The monitor is
   protected for most of the time with no access flags. However, our unprotected
   code needs to be able to run even when the monitor is not allowed to. This
   would be easiest to accomplish if we could simply add a new separate segment
   that the loader could load with separate access rights. However, the GNU
   linker does not seem to make that easy at all. It would have to be done
   through the PHDRS command; but using it will discard all the default PHDRS,
   and it is not documented anywhere what those are.

   Apparently, mapping sections to segments happens linearly through the file
   offsets. So, if we add our unprotected section at the very end of the last
   section that also is in the executable segment, we can simply mprotect
   only the first part of the segment, and leave the last section unprotected. 
   That's what we do here.
*/
SECTIONS 
{ 
	unprotected ALIGN(0x1000): 
	{
		__unprotected_start = .;
		*(unprotected)
		. = ALIGN(0x1000);
		__unprotected_end = .;
	}
}
INSERT AFTER .eh_frame;


SECTIONS 
{
   protected_state ALIGN(0x1000):
   {
      __protected_state_start = .;
      *(protected_state)
      __protected_state_end = .;
   }
}
INSERT AFTER .data;

SECTIONS {
      __start__ = .;
}
INSERT BEFORE .hash;  
