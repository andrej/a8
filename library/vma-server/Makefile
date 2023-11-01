# This file is to be called from the parent directory's Makefile and assumes
# the current working directory is there, as well as INCLUDE_DIRS, CC 
# and BUILD_DIR variables set.

$(BUILD_DIR)/vma-server: vma-server/vma_server.c
	$(CC) -g $(INCLUDE_DIRS:%=-I%) -pthread -o $@ $^ -lrt