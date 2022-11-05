
#include <linux/module.h>
#include "util.h"
#include "config.h"


/* ************************************************************************** *
 * Internal Macros                                                            *
 * ************************************************************************** */

#if !MONMOD_SKIP_SANITY_CHECKS
#define _config_sanity_checks(else) { \
    if(NULL == monmod_global_config.kobj) { \
        else; \
    } \
}
#else
#define _config_sanity_checks(else)  
#endif


/* ************************************************************************** *
 * Global Variables                                                           *
 * ************************************************************************** */

struct monmod_config monmod_global_config = {};


/* ************************************************************************** *
 * Internal Variables                                                         *
 * ************************************************************************** */

static struct kobj_attribute pid_attribute = 
    __ATTR(pid, 0664, _monmod_config_pid_show, _monmod_config_pid_store);
static struct kobj_attribute traced_syscalls_attribute = 
    __ATTR(traced_syscalls, 0664, _monmod_config_traced_syscalls_show, 
           _monmod_config_traced_syscalls_store);

static struct attribute *attrs[] = {
    &pid_attribute.attr,
    &traced_syscalls_attribute.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = attrs,
};


/* ************************************************************************** *
 * API Functions                                                              *
 * ************************************************************************** */

int monmod_config_init()
{
    struct kobject *config_kobject = NULL;
    if(NULL != monmod_global_config.kobj) {
        return 1;
    }
    memset(&monmod_global_config, 0, sizeof(monmod_global_config));
    config_kobject = kobject_create_and_add("monmod", kernel_kobj);
    if(NULL == config_kobject) {
        return 1;
    }
    if(0 != sysfs_create_group(config_kobject, &attr_group)) {
        kobject_put(config_kobject);
    }
    monmod_global_config.kobj = config_kobject;
    return 0;
}

void monmod_config_free()
{
    if(monmod_global_config.kobj == NULL) {
        return;
    }
    kobject_put(monmod_global_config.kobj);
    monmod_global_config.kobj = NULL;
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

ssize_t _monmod_config_pid_show(struct kobject *kobj, 
                                struct kobj_attribute *attr, 
                                char *buf)
{
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }
    return snprintf(buf, PAGE_SIZE, "%d\n", 
                    monmod_global_config.tracee_pid);
}

ssize_t _monmod_config_pid_store(struct kobject *kobj, 
                                 struct kobj_attribute *attr, 
                                 const char *buf, 
                                 size_t count)
{
    int ret = -1;
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }
    TRY(ret = kstrtoint(buf, 10, &monmod_global_config.tracee_pid),
        return -1);
    return count;
}

ssize_t _monmod_config_traced_syscalls_show(struct kobject *kobj, 
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
        if(monmod_syscall_is_active(no)) {
            n_written += snprintf(buf + n_written, PAGE_SIZE - n_written,
                                  "%llu\n", no);
        }
    }
    return n_written;
}

ssize_t _monmod_config_traced_syscalls_store(struct kobject *kobj, 
                                             struct kobj_attribute *attr, 
                                             const char *buf, 
                                             size_t count)
{
    size_t consumed = 0;
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }

    memset((void *)&monmod_global_config.syscall_masks, 
           0, sizeof(monmod_global_config.syscall_masks));

    while(consumed < count) {
        int no = 0;
        ssize_t line_len = next_int_line(buf + consumed, count - consumed, &no);
        if(line_len < 0) {
            MONMOD_WARNF("Parsing configuration: Invalid input at offset %lu", 
                         consumed);
        }
        if(line_len == 0) {
            break;
        }
        if(!monmod_syscall_is_active(no)) {
            if(0 != monmod_syscall_activate(no)) {
                MONMOD_WARNF("Reading config: Cannot activate tracing for "
                             "syscall no %d", no);
                return -1;
            }
        }
        consumed += line_len;
    }
    return consumed;
}
