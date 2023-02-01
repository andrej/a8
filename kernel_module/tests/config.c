#include <stdlib.h>  // malloc 
#include <string.h>  // strcmp
#include "mocks.h"
#include "test_suite/test.h"
#include "../include/config.h"
#include "../include/tracee_info.h"

// Mock needed for running tests outside kernel ...
struct sysfs_ops kobj_sysfs_ops = {};

TEST(global_config)
{
	int i = 0;
	fflush(stdout);
	ASSERT_EQ(monmod_global_config.n_tracees, 0);
	for(i = 0; i < MONMOD_N_SYSCALL_MASKS; i++) {
		ASSERT(monmod_global_config.syscall_masks[i] == 0);
	}
	return 0;
}

TEST(config_struct)
{
	struct monmod_config conf = {};
	ASSERT(sizeof(conf) > sizeof(u64));
	ASSERT_EQ(conf.n_tracees, 0);
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
	u64 no;
	monmod_global_config = (struct monmod_config){};
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

	for(no = 0; no < __NR_syscalls; no++) {
		ASSERT(monmod_syscall_is_active(no) == 0);
		ASSERT(monmod_syscall_activate(no) == 0);
		ASSERT(monmod_syscall_activate(no) == 1);
		ASSERT(monmod_syscall_is_active(no) == 1);
		ASSERT(monmod_syscall_deactivate(no) == 0);
		ASSERT(monmod_syscall_deactivate(no) == 1);
	}
	return 0;
}

int mocked_kobject_init_and_add_calls = 0;
MOCK(int, kobject_init_and_add, 
     struct kobject *kobject,
     struct kobj_type *ktype,
     struct kobject *parent,
     const char *name)
{
	mocked_kobject_init_and_add_calls += 1;
	kobject->name = name;
	kobject->parent = parent;
	return 0;
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
	int prev_calls = mocked_kobject_init_and_add_calls;
	monmod_global_config = (struct monmod_config){};
	ASSERT(monmod_config_init() == 0);
	ASSERT(mocked_kobject_init_and_add_calls == prev_calls + 1);
	ASSERT(monmod_global_config.kobj.parent == kernel_kobj);
	ASSERT(strcmp(monmod_global_config.kobj.name, "monmod") == 0);
	return 0;
}

TEST(_config_show_traced_syscalls)
{
	struct kobject kobj_a = {};
	monmod_global_config = (struct monmod_config){};
	ASSERT(_monmod_config_untraced_syscalls_show(NULL, NULL, NULL) < 0);
	ASSERT(_monmod_config_untraced_syscalls_show(&kobj_a, NULL, NULL) < 0);
	return 0;
}

int mocked_kobject_put_calls = 0;
MOCK(void, kobject_put, struct kobject *kobj)
{
	mocked_kobject_put_calls += 1;
}

TEST(monmod_config_free)
{
	int prev_calls = mocked_kobject_put_calls;
	monmod_config_free();
	ASSERT(mocked_kobject_put_calls = prev_calls+1);
	return 0;
}

TEST(config_untraced_syscalls_store)
{
	struct kobject *kobj = &monmod_global_config.kobj;
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
	monmod_global_config.kobj.name = "monmod";
	attr.name = "traced_syscalls";

	ASSERT_EQ(sizeof(buf1), _monmod_config_untraced_syscalls_store(
		kobj, &attr, buf1, sizeof(buf1)));
	ASSERT_EQ(1, monmod_syscall_is_active(1));
	ASSERT_EQ(1, monmod_syscall_is_active(99));
	ASSERT_EQ(1, monmod_syscall_is_active(5));
	ASSERT_EQ(0, monmod_syscall_is_active(123));
	ASSERT_EQ(0, monmod_syscall_is_active(45));
	ASSERT_EQ(0, monmod_syscall_is_active(6));

	ASSERT_EQ(-1, _monmod_config_untraced_syscalls_store(
		kobj, &attr, buf2, sizeof(buf2)));
	ASSERT_EQ(1, monmod_syscall_is_active(1));
	ASSERT_EQ(1, monmod_syscall_is_active(123));
	ASSERT_EQ(1, monmod_syscall_is_active(45));
	ASSERT_EQ(1, monmod_syscall_is_active(6));
	ASSERT_EQ(0, monmod_syscall_is_active(99));
	ASSERT_EQ(0, monmod_syscall_is_active(5));
	ASSERT_EQ(1, monmod_syscall_is_active(2));

	ASSERT_EQ(sizeof(buf3), _monmod_config_untraced_syscalls_store(
		kobj, &attr, buf3, sizeof(buf3)));
	ASSERT_EQ(1, monmod_syscall_is_active(1));
	ASSERT_EQ(1, monmod_syscall_is_active(123));
	ASSERT_EQ(1, monmod_syscall_is_active(45));
	ASSERT_EQ(1, monmod_syscall_is_active(6));
	ASSERT_EQ(1, monmod_syscall_is_active(99));
	ASSERT_EQ(1, monmod_syscall_is_active(5));
	ASSERT_EQ(1, monmod_syscall_is_active(2));
	return 0;
}

MOCK(void, kfree, void)
{ }

/*MOCK(int, rcu_read_lock_held, void)
{ return 0; }*/

MOCK(long, _raw_spin_lock_irqsave, long a, long b)
{ return 0; }

MOCK(long, _raw_spin_unlock_irqrestore, long a, long b)
{ return 0; }

TEST(_config_show_tracee_pids)
{
	ssize_t ret;
	struct kobject *kobj = &monmod_global_config.kobj;
	struct kobj_attribute attr = {};
	char buf[PAGE_SIZE] = "";
	char target_buf1[] = "32\n"
	                   "42\n"
	                   "57\n";
	char target_buf2[] = "42\n";
	monmod_global_config = (struct monmod_config){};
	add_tracee_info(32);
	add_tracee_info(42);
	add_tracee_info(57);
	ret = _monmod_config_tracee_pids_show(kobj, &attr, buf);
	ASSERT_EQ(ret, sizeof(target_buf1));
	ASSERT_EQ(strcmp(buf, target_buf1), 0);
	del_tracee_info(get_tracee_info(32));
	del_tracee_info(get_tracee_info(57));
	ASSERT_EQ(_monmod_config_tracee_pids_show(kobj, &attr, buf),
	          sizeof(target_buf2));
	ASSERT_EQ(strcmp(buf, target_buf2), 0);
	return 0;
}

TEST(config_store_tracee_pids)
{
	struct kobject *kobj = &monmod_global_config.kobj; 
	struct kobj_attribute attr = {};
	monmod_global_config = (struct monmod_config){};
	kobj->name = "monmod";
	attr.name = "untraced_syscalls";

	ASSERT_NEQ(NULL, add_tracee_info(45));
	ASSERT_NEQ(NULL, add_tracee_info(6));
	ASSERT_NEQ(NULL, add_tracee_info(123));

	ASSERT_EQ(NULL,  get_tracee_info(1));
	ASSERT_EQ(NULL,  get_tracee_info(99));
	ASSERT_EQ(NULL,  get_tracee_info(5));
	ASSERT_NEQ(NULL, get_tracee_info(123));
	ASSERT_NEQ(NULL, get_tracee_info(45));
	ASSERT_NEQ(NULL, get_tracee_info(6));

	free_tracee_infos();
	ASSERT_EQ(NULL, get_tracee_info(1));
	ASSERT_EQ(NULL, get_tracee_info(123));
	ASSERT_EQ(NULL, get_tracee_info(45));
	ASSERT_EQ(NULL, get_tracee_info(6));
	ASSERT_EQ(NULL, get_tracee_info(99));
	ASSERT_EQ(NULL, get_tracee_info(5));
	ASSERT_EQ(NULL, get_tracee_info(2));

	return 0;
}
