# This file is to be called from the parent directory's Makefile and assumes
# the current working directory is there, as well as INCLUDE_DIRS, CC 
# and BUILD_DIR variables set.

DEP      := $(BUILD_DIR)/vma-server.d
$(BUILD_DIR)/vma-server: vma-server/vma_server.c
	$(CC) -g $(INCLUDE_DIRS:%=-I%) -pthread -MM -MT $@ -MF $(DEP) $<
	$(CC) -g $(INCLUDE_DIRS:%=-I%) -pthread -o $@ $< -lrt

-include $(DEP)