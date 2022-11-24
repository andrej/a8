SECTIONS { 
	tests : {
		__tests_start = .;
		*(tests)
		__tests_end = .;
	}
}
INSERT AFTER .rodata;
