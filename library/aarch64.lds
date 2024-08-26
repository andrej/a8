/* See docs/linking.md for an explanation why we need a custom linker script.
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
   __monitor_start = .;
}
INSERT BEFORE .hash;  

SECTIONS {
   __monitor_end = .;
}
INSERT AFTER .bss;
