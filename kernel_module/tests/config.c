#include <stdlib.h>  // malloc 
#include <string.h>  // strcmp
#include "mocks.h"
#include "test_suite/test.h"
#include "../include/config.h"

TEST(global_config)
{
	fflush(stdout);
	ASSERT(monmod_global_config.kobj == NULL);
	ASSERT(monmod_global_config.tracee_pid == 0);
	for(int i = 0; i < MONMOD_N_SYSCALL_MASKS; i++) {
		ASSERT(monmod_global_config.syscall_masks[i] == 0);
	}
	return 0;
}

TEST(config_struct)
{
	struct monmod_config conf = {};
	ASSERT(sizeof(conf) > sizeof(u64));
	ASSERT(conf.tracee_pid == 0);
	ASSERT(MONMOD_N_SYSCALL_MASKS > 0);
	ASSERT(MONMOD_N_SYSCALL_MASKS < 32);
	return 0;
}

TEST(mask_index)
{
	ASSERT(_monmod_syscall_mask_index(0) == 0);
	ASSERT(_monmod_syscall_mask_index(1) == 0);
	ASSERT(_monmod_syscall_mask_index(32) == 0);
	ASSERT(_monmod_syscall_mask_index(63) == 0);
	ASSERT(_monmod_syscall_mask_index(64) == 1);
	ASSERT(_monmod_syscall_mask_index(65) == 1);
	ASSERT(_monmod_syscall_mask_index(__NR_syscalls-1) >= 0);
	ASSERT(_monmod_syscall_mask_index(__NR_syscalls-1) == MONMOD_N_SYSCALL_MASKS-1);
	ASSERT(_monmod_syscall_mask_index(__NR_syscalls) < 0);
	return 0;
}

TEST(mask_offset)
{
	ASSERT(_monmod_syscall_mask_offset(0) == 0);
	ASSERT(_monmod_syscall_mask_offset(1) == 1);
	ASSERT(_monmod_syscall_mask_offset(32) == 32);
	ASSERT(_monmod_syscall_mask_offset(63) == 63);
	ASSERT(_monmod_syscall_mask_offset(64) == 0);
	ASSERT(_monmod_syscall_mask_offset(65) == 1);
	ASSERT(_monmod_syscall_mask_offset(__NR_syscalls) < 0);
	return 0;
}

TEST(mask_activate_deactivate)
{
	monmod_global_config = (struct monmod_config){};
	monmod_global_config.kobj = (struct kobject *)0x01;
	ASSERT(monmod_syscall_is_active(0) == 0);
	ASSERT(monmod_syscall_is_active(1) == 0);
	ASSERT(monmod_syscall_is_active(7) == 0);
	ASSERT(monmod_syscall_is_active(63) == 0);
	ASSERT(monmod_syscall_is_active(64) == 0);
	ASSERT(monmod_syscall_is_active(65) == 0);

	ASSERT(monmod_syscall_activate(7) == 0);
	ASSERT(monmod_syscall_activate(7) == 1);
	ASSERT(monmod_syscall_is_active(0) == 0);
	ASSERT(monmod_syscall_is_active(1) == 0);
	ASSERT(monmod_syscall_is_active(63) == 0);
	ASSERT(monmod_syscall_is_active(64) == 0);
	ASSERT(monmod_syscall_is_active(65) == 0);
	ASSERT(monmod_syscall_is_active(7) == 1);

	ASSERT(monmod_syscall_activate(65) == 0);
	ASSERT(monmod_syscall_is_active(65) == 1);

	ASSERT(monmod_syscall_deactivate(7) == 0);
	ASSERT(monmod_syscall_deactivate(7) == 1);
	ASSERT(monmod_syscall_is_active(7) == 0);

	ASSERT(monmod_syscall_is_active(65) == 1);
	ASSERT(monmod_syscall_deactivate(65) == 0);
	ASSERT(monmod_syscall_deactivate(65) == 1);
	ASSERT(monmod_syscall_is_active(65) == 0);

	for(u64 no = 0; no < __NR_syscalls; no++) {
		ASSERT(monmod_syscall_is_active(no) == 0);
		ASSERT(monmod_syscall_activate(no) == 0);
		ASSERT(monmod_syscall_activate(no) == 1);
		ASSERT(monmod_syscall_is_active(no) == 1);
		ASSERT(monmod_syscall_deactivate(no) == 0);
		ASSERT(monmod_syscall_deactivate(no) == 1);
	}
	return 0;
}

int mocked_kobject_create_and_add_calls = 0;
MOCK(struct kobject *, kobject_create_and_add, const char *name, 
     struct kobject *parent)
{
	mocked_kobject_create_and_add_calls += 1;
	struct kobject *kobj = malloc(sizeof(struct kobject));
	if(!kobj) {
		printf("Out of memory!");
		raise(SIGSEGV);
	}
	kobj->name = name;
	kobj->parent = parent;
	return kobj;
}

int mocked_sysfs_create_group_calls = 0;
MOCK(int, sysfs_create_group, struct kobject *kobj,
     const struct attribute_group *grp)
{
	mocked_sysfs_create_group_calls += 1;
	return 0;
}

struct kobject *kernel_kobj = (struct kobject *)0xFF;

TEST(monmod_config_init)
{
	// reset config object from any previous tests
	monmod_global_config = (struct monmod_config){};
	int prev_calls = mocked_kobject_create_and_add_calls;
	ASSERT(monmod_config_init() == 0);
	ASSERT(mocked_kobject_create_and_add_calls == prev_calls + 1);
	ASSERT(monmod_global_config.kobj != NULL);
	ASSERT(monmod_global_config.kobj->parent == kernel_kobj);
	ASSERT(strcmp(monmod_global_config.kobj->name, "monmod") == 0);
	ASSERT(monmod_config_init() == 1);  // repeated calls not ok
	if(monmod_global_config.kobj != NULL) {
		free(monmod_global_config.kobj);
		monmod_global_config.kobj = NULL;
	}
	return 0;
}

TEST(_config_show_traced_syscalls)
{
	struct kobject kobj_a = {};
	struct kobject kobj_b = {};
	char buf[PAGE_SIZE] = "";
	monmod_global_config = (struct monmod_config){};
	monmod_global_config.kobj = &kobj_a;
	ASSERT(_monmod_config_traced_syscalls_show(NULL, NULL, NULL) < 0);
	ASSERT(_monmod_config_traced_syscalls_show(&kobj_a, NULL, NULL) < 0);
	// for safety, method should only work if container_of(kobj) is 
	// monmod_global_config
	ASSERT(_monmod_config_traced_syscalls_show(&kobj_b, NULL, buf) < 0);
	ASSERT(_monmod_config_traced_syscalls_show(&kobj_a, NULL, buf) < 0);
	monmod_global_config.kobj = NULL;
	return 0;
}

int mocked_kobject_put_calls = 0;
MOCK(void, kobject_put, struct kobject *kobj)
{
	mocked_kobject_put_calls += 1;
	if(kobj) {
		free(kobj);
	}
}

TEST(monmod_config_free)
{
	int prev_calls = mocked_kobject_put_calls;
	monmod_config_free();
	ASSERT(mocked_kobject_put_calls = prev_calls+1);
	ASSERT(monmod_global_config.kobj == NULL);
	return 0;
}

TEST(config_traced_syscalls_store)
{
	struct kobject kobj = {};
	struct kobj_attribute attr = {};
	const char buf1[] = "123\n"
		"45\n"
		"\n"
		"6";
	const char buf2[] = "99\n"
		"5\n"
		"kk\n"
		"2\n";
	const char buf3[] = { '\n' };
	monmod_global_config = (struct monmod_config){};
	monmod_global_config.kobj = &kobj;
	kobj.name = "monmod";
	attr.name = "traced_syscalls";

	ASSERT_EQ(sizeof(buf1), _monmod_config_traced_syscalls_store(
		&kobj, &attr, buf1, sizeof(buf1)));
	ASSERT_EQ(0, monmod_syscall_is_active(1));
	ASSERT_EQ(0, monmod_syscall_is_active(99));
	ASSERT_EQ(0, monmod_syscall_is_active(5));
	ASSERT_EQ(1, monmod_syscall_is_active(123));
	ASSERT_EQ(1, monmod_syscall_is_active(45));
	ASSERT_EQ(1, monmod_syscall_is_active(6));

	ASSERT_EQ(-1, _monmod_config_traced_syscalls_store(
		&kobj, &attr, buf2, sizeof(buf2)));
	ASSERT_EQ(0, monmod_syscall_is_active(1));
	ASSERT_EQ(0, monmod_syscall_is_active(123));
	ASSERT_EQ(0, monmod_syscall_is_active(45));
	ASSERT_EQ(0, monmod_syscall_is_active(6));
	ASSERT_EQ(1, monmod_syscall_is_active(99));
	ASSERT_EQ(1, monmod_syscall_is_active(5));
	ASSERT_EQ(0, monmod_syscall_is_active(2));


	ASSERT_EQ(sizeof(buf3), _monmod_config_traced_syscalls_store(
		&kobj, &attr, buf3, sizeof(buf3)));
	ASSERT_EQ(0, monmod_syscall_is_active(1));
	ASSERT_EQ(0, monmod_syscall_is_active(123));
	ASSERT_EQ(0, monmod_syscall_is_active(45));
	ASSERT_EQ(0, monmod_syscall_is_active(6));
	ASSERT_EQ(0, monmod_syscall_is_active(99));
	ASSERT_EQ(0, monmod_syscall_is_active(5));
	ASSERT_EQ(0, monmod_syscall_is_active(2));
	return 0;
}
