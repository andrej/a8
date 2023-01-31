#include <linux/module.h>
#include <linux/spinlock.h>
#include "util.h"
#include "config.h"
#include "tracee_info.h"


/* ************************************************************************** *
 * Internal Macros                                                            *
 * ************************************************************************** */

#if !MONMOD_SKIP_SANITY_CHECKS
#define _config_sanity_checks(else) { \
}
#else
#define _config_sanity_checks(else)  
#endif


/* ************************************************************************** *
 * Global Variables                                                           *
 * ************************************************************************** */

struct monmod_config monmod_global_config = {};

/* The mutex is held whenever a new tracee is added or deleted.
   RCU is used for readers that need to get the tracee config on each system 
   call. */
DEFINE_SPINLOCK(monmod_tracees_lock);


/* ************************************************************************** *
 * Internal Variables                                                         *
 * ************************************************************************** */

#define ATTRIBUTE_DEF(name) \
    static struct kobj_attribute name ## _attribute =  \
        __ATTR(name, 0664, _monmod_config_ ## name ## _show, \
            _monmod_config_ ## name ## _store);
GLOBAL_ATTRIBUTES(ATTRIBUTE_DEF)
TRACEE_ATTRIBUTES(ATTRIBUTE_DEF)
#undef ATTRIBUTE_DEF

#define ATTRIBUTE_REF(name) \
    &name ## _attribute.attr,
static struct attribute *attrs[] = {
    GLOBAL_ATTRIBUTES(ATTRIBUTE_REF)
    NULL
};
static struct attribute *tracee_attrs[] = {
    TRACEE_ATTRIBUTES(ATTRIBUTE_REF)
    NULL
};
#undef ATTRIBUTE_REF

static struct attribute_group global_attr_group = {
    .attrs = attrs,
};

static struct attribute_group tracee_attr_group = {
    .attrs = tracee_attrs,
};

void static_kobj_release(struct kobject *kobj)
{
    memset(kobj, 0, sizeof(struct kobject));
    return;
}

static struct kobj_type static_kobj_ktype = {
    .release = static_kobj_release,
    .sysfs_ops = &kobj_sysfs_ops
};


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int monmod_config_init()
{
    int s = 0;
    memset(&monmod_global_config, 0, sizeof(monmod_global_config));
    memset((void *)&monmod_global_config.syscall_masks, 
           ~0U, sizeof(monmod_global_config.syscall_masks));
    s = kobject_init_and_add(&monmod_global_config.kobj, 
                             &static_kobj_ktype,
                             kernel_kobj,
                             "monmod");
    if(0 != s) {
        return 1;
    }
    if(0 != sysfs_create_group(&monmod_global_config.kobj, &global_attr_group))
    {
        kobject_put(&monmod_global_config.kobj);
        return 1;
    }
    return 0;
}

void monmod_config_free()
{
    monmod_global_config.n_tracees = 0;
    kobject_put(&monmod_global_config.kobj);
    memset(&monmod_global_config, 0, sizeof(monmod_global_config));
}

int monmod_tracee_config_init(pid_t pid, struct monmod_tracee_config *conf)
{
    struct kobject *config_kobject = NULL;
    struct kobject *root_kobject = NULL;
    char name[16];
    int s = 0;

    // Sanity checks 
    root_kobject = &monmod_global_config.kobj;
    config_kobject = &conf->kobj;

    s = snprintf(name, sizeof(name), "%d", pid);
    if(0 > s || s >= sizeof(name)) {
        return 1;
    }
    s = kobject_init_and_add(config_kobject, 
                             &static_kobj_ktype,
                             root_kobject,
                             name);
    if(0 != s) {
        return 1;
    }
    if(0 != sysfs_create_group(config_kobject, &tracee_attr_group)) {
        kobject_put(config_kobject);
        return 1;
    }
    return 0;
}

void monmod_tracee_config_free(struct monmod_tracee_config *conf)
{
    if(NULL == conf) {
        return;
    }
    kobject_put(&conf->kobj);
}

int monmod_syscall_is_active(u64 syscall_no)
{
    int index, offset;
    _config_sanity_checks(return 0);   
    index = _monmod_syscall_mask_index(syscall_no);
    offset = _monmod_syscall_mask_offset(syscall_no);
    if(index < 0 || offset < 0) {
        return 0;
    }
    return (monmod_global_config.syscall_masks[index] >> offset) & 0x1;
}

int monmod_syscall_activate(u64 syscall_no)
{
    int index, offset;
    _config_sanity_checks(return 1);
    index = _monmod_syscall_mask_index(syscall_no);
    offset = _monmod_syscall_mask_offset(syscall_no);
    if(index < 0 || offset < 0) {
        return 1;
    }
    if(monmod_syscall_is_active(syscall_no)) {
        return 1;
    }
    monmod_global_config.syscall_masks[index] |= 1UL << offset;
    return 0;
}

int monmod_syscall_deactivate(u64 syscall_no)
{
    int index, offset;
    _config_sanity_checks(return 1);
    index = _monmod_syscall_mask_index(syscall_no);
    offset = _monmod_syscall_mask_offset(syscall_no);
    if(index < 0 || offset < 0) {
        return 1;
    }
    if(!monmod_syscall_is_active(syscall_no)) {
        return 1;
    }
    monmod_global_config.syscall_masks[index] &= ~(1UL << offset);
    return 0;
}


/* ************************************************************************** *
 * Internal Functions                                                         *
 * ************************************************************************** */

inline int _monmod_syscall_mask_index(u64 no)
{
    int res;
    if(no >= __NR_syscalls) {
        return -1;
    }
    res = no / MONMOD_BITS_PER_MASK;
#if !MONMOD_SKIP_SANITY_CHECKS
    if(res > MONMOD_N_SYSCALL_MASKS) {
        return -1;
    }
#endif
    return res;
}

inline int _monmod_syscall_mask_offset(u64 no)
{
    int res;
    if(no >= __NR_syscalls) {
        return -1;
    }
    res = no % MONMOD_BITS_PER_MASK;
    return res;
}

static inline int _config_callback_sanity_checks(const struct kobject *kobj,
                                                 const struct kobj_attribute *attr,
                                                 const char *buf)
{
    if(NULL == kobj || NULL == attr || NULL == buf) {
        printk(KERN_WARNING "monmod: _config_callback_sanity_checks failed."
               "<kobj: %p> <attr: %p> <buf: %p>\n", kobj, attr, buf);
        return 1;
    }
    return 0;
}


/* ************************************************************************** *
 * Generic Setting Store / Show Callbacks                                     *
 * ************************************************************************** */

ssize_t _monmod_config_long_show(struct kobject *kobj, 
                                 struct kobj_attribute *attr, 
                                 char *buf,
                                 long val)
{
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }
    return snprintf(buf, PAGE_SIZE, "%ld\n", val);
}

ssize_t _monmod_config_int_or_long_store(struct kobject *kobj, 
                                         struct kobj_attribute *attr, 
                                         const char *buf, 
                                         size_t count,
                                         bool is_long,
                                         long *dest)
{
    int ret = -1;
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }
    if(is_long) {
        TRY(ret = kstrtol(buf, 10, dest),
            return -1);
    } else {
        TRY(ret = kstrtoint(buf, 10, (int *)dest),
            return -1);
    }
    return count;
}

#define CONFIG_LONG_SHOW_FUN(name, container_type, member_name) \
    ssize_t _monmod_config_ ## name ## _show(struct kobject *kobject,  \
                                             struct kobj_attribute *attr, \
                                             char *buf) \
    { \
        container_type *src = container_of(kobject, container_type, kobj); \
        ssize_t ret = _monmod_config_long_show( \
                        kobject, attr, buf, \
                        (long)src->member_name); \
        return ret; \
    } 

#define CONFIG_LONG_STORE_FUN(name, container_type, member_name, is_long) \
    ssize_t _monmod_config_ ## name ## _store(struct kobject *kobject, \
                                              struct kobj_attribute *attr, \
                                              const char *buf, \
                                              size_t count) \
    { \
        container_type *dst = container_of(kobject, container_type, kobj); \
        ssize_t ret = _monmod_config_int_or_long_store( \
                        kobject, attr, buf, count, is_long, \
                        (long *)&dst->member_name); \
        if(0 < ret) { \
            printk(KERN_INFO "monmod: Set configuration " #name " to %ld\n", \
                (long)dst->member_name); \
        } else { \
            printk(KERN_WARNING "monmod: Failed to set configuration " #name \
                   " with return value %ld\n", ret); \
        } \
        return ret; \
    }


/* ************************************************************************** *
 * Config Setting Store / Show Callbacks                                      *
 * ************************************************************************** */

CONFIG_LONG_SHOW_FUN(trusted_addr, struct monmod_tracee_config, trusted_addr)
CONFIG_LONG_STORE_FUN(trusted_addr, struct monmod_tracee_config, trusted_addr, 
                      true)

CONFIG_LONG_SHOW_FUN(monitor_start, struct monmod_tracee_config, monitor_start)
CONFIG_LONG_STORE_FUN(monitor_start, struct monmod_tracee_config, monitor_start, 
                      true)

CONFIG_LONG_SHOW_FUN(monitor_len, struct monmod_tracee_config, monitor_len)
CONFIG_LONG_STORE_FUN(monitor_len, struct monmod_tracee_config, monitor_len, 
                      true)

CONFIG_LONG_SHOW_FUN(trace_func_addr, struct monmod_tracee_config, 
                     trace_func_addr)
CONFIG_LONG_STORE_FUN(trace_func_addr, struct monmod_tracee_config, 
                      trace_func_addr, true)

CONFIG_LONG_SHOW_FUN(active, struct monmod_config, active)
CONFIG_LONG_STORE_FUN(active, struct monmod_config, active, false)


ssize_t _monmod_config_tracee_pids_show(struct kobject *kobject, 
                                        struct kobj_attribute *attr,
                                        char *buf)
{
    size_t n_written = 0;
    size_t i = 0;
    if(0 != _config_callback_sanity_checks(kobject, attr, buf)) {
        return -1;
    }
    rcu_read_lock();
    for(i = 0; i < MAX_N_TRACEES; i++) {
        if(TRACEE_INFO_VALID != tracees[i].state) {
            continue;
        }
        n_written += snprintf(buf + n_written, PAGE_SIZE - n_written,
                              "%d\n", tracees[i].pid);
    }
    rcu_read_unlock();
    if(n_written > 0 && n_written < PAGE_SIZE) {
        // Include terminating NULL in n_written count
        n_written += 1;
    }
    return n_written;
}

ssize_t _monmod_config_tracee_pids_store(struct kobject *kobj,
                                         struct kobj_attribute *attr,
                                         const char *buf,
                                         size_t count)
{
    /* Adding new tracees through sysfs is no longer supported. Use the
       __NR_monmod_init system call instead. */
    return -1;
}

ssize_t _monmod_config_untraced_syscalls_show(struct kobject *kobj, 
                                              struct kobj_attribute *attr, 
                                              char *buf)
{
    size_t n_written = 0;
    u64 no = 0;
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }
    buf[0] = '\0';
    for(no = 0; no < __NR_syscalls && n_written < PAGE_SIZE; no++) {
        if(!monmod_syscall_is_active(no)) {
            n_written += snprintf(buf + n_written, PAGE_SIZE - n_written,
                                  "%llu\n", no);
        }
    }
    return n_written;
}

ssize_t _monmod_config_untraced_syscalls_store(struct kobject *kobj, 
                                               struct kobj_attribute *attr, 
                                               const char *buf, 
                                               size_t count)
{
    size_t consumed = 0;
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }

    // By default, mark everything traced
    memset((void *)&monmod_global_config.syscall_masks, 
           ~0U, sizeof(monmod_global_config.syscall_masks));

    while(consumed < count) {
        int no = 0;
        ssize_t line_len = next_int_line(buf + consumed, count - consumed, &no);
        if(line_len < 0) { // Invalid input encountered.
            MONMOD_WARNF("Parsing configuration: Invalid input at offset %lu", 
                         consumed);
            return -1;
        }
        if(line_len == 0) { // No input numbers remaining; everything was valid.
            consumed = count;
            break;
        }
        if(monmod_syscall_is_active(no)) {
            if(0 != monmod_syscall_deactivate(no)) {
                MONMOD_WARNF("Reading config: Cannot deactivate tracing for "
                             "syscall no %d", no);
                return -1;
            } else {
                printk(KERN_INFO "monmod: Deactivated tracing of system call "
                       "%d\n", no);
            }
        }
        consumed += line_len;
    }

    printk(KERN_INFO "monmod: Traced syscalls configuration updated\n");

    return consumed;
}
