#include <linux/module.h>
#include "util.h"
#include "config.h"


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


/* ************************************************************************** *
 * Internal Variables                                                         *
 * ************************************************************************** */

// FIXME In the following two, set more reasonable file permissions
// (probably 0664)
static struct kobj_attribute tracee_pids_attribute = 
    __ATTR(tracee_pids, 0664, _monmod_config_tracee_pids_show, 
           _monmod_config_tracee_pids_store);
static struct kobj_attribute tracee_pids_add_attribute = 
    __ATTR(tracee_pids_add, 0664, _monmod_config_tracee_pids_add_show, 
           _monmod_config_tracee_pids_add_store);
static struct kobj_attribute trusted_addr_attribute = 
    __ATTR(trusted_addr, 0664, _monmod_config_trusted_addr_show, 
           _monmod_config_trusted_addr_store);
static struct kobj_attribute trace_func_addr_attribute = 
    __ATTR(trace_func_addr, 0664, _monmod_config_trace_func_addr_show, 
           _monmod_config_trace_func_addr_store);
static struct kobj_attribute active_attribute = 
    __ATTR(active, 0664, _monmod_config_active_show, 
           _monmod_config_active_store);
static struct kobj_attribute untraced_syscalls_attribute = 
    __ATTR(untraced_syscalls, 0664, _monmod_config_untraced_syscalls_show, 
           _monmod_config_untraced_syscalls_store);

static struct attribute *attrs[] = {
    &tracee_pids_attribute.attr,
    &tracee_pids_add_attribute.attr,
    &active_attribute.attr,
    &untraced_syscalls_attribute.attr,
    NULL
};

static struct attribute_group attr_group = {
    .attrs = attrs,
};

static struct attribute *tracee_attrs[] = {
    &trusted_addr_attribute.attr,
    &trace_func_addr_attribute.attr,
    NULL
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
    if(0 != sysfs_create_group(&monmod_global_config.kobj, &attr_group)) {
        kobject_put(&monmod_global_config.kobj);
        return 1;
    }
    return 0;
}

void monmod_config_free()
{
    int i = 0;
    for(i = 0; i < monmod_global_config.n_tracees; i++) {
        monmod_tracee_config_free(i);
    }
    monmod_global_config.n_tracees = 0;
    kobject_put(&monmod_global_config.kobj);
    memset(&monmod_global_config, 0, sizeof(monmod_global_config));
}

int monmod_add_tracee_config(pid_t pid)
{
    size_t idx = 0;

    if(monmod_global_config.n_tracees >= MONMOD_MAX_N_TRACEES) {
        MONMOD_WARN("Adding tracee config, exhausted capacity.\n");
        return 1;
    }
    idx = 0;
    // Find free slot to put this tracee config
    for(; idx < MONMOD_MAX_N_TRACEES; idx++) {
        if(0 == monmod_global_config.tracee_pids[idx]) {
            break;
        }
    }
    if(idx > MONMOD_MAX_N_TRACEES) {
        MONMOD_WARN("Adding tracee config, sanity check failed!\n");
        return 1;
    }
    // Reset tracee configuration, make sure we start from a clean slate
    memset(&monmod_global_config.tracees[idx], 0, 
           sizeof(monmod_global_config.tracees[0]));
    monmod_global_config.tracee_pids[idx] = pid;
    monmod_tracee_config_init(idx);
    monmod_global_config.n_tracees++;
    return 0;
}

int monmod_del_tracee_config(size_t idx)
{
    // Sanity checks
    if(0 >= monmod_global_config.n_tracees
       || monmod_global_config.n_tracees > MONMOD_MAX_N_TRACEES) {
        return 1;
    }
    monmod_tracee_config_free(idx);
    monmod_global_config.tracee_pids[idx] = 0;
    monmod_global_config.n_tracees--;
    return 0;
}

struct monmod_tracee_config *monmod_get_tracee_config(pid_t pid)
{
    int i = 0;
    for(; i < MONMOD_MAX_N_TRACEES; i++) {
        if(0 == monmod_global_config.tracee_pids[i]) {
            continue;
        }
        if(monmod_global_config.tracee_pids[i] == pid) {
            return &monmod_global_config.tracees[i];
        }
    }
    return NULL;
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


int monmod_tracee_config_init(size_t idx)
{
    struct kobject *config_kobject = NULL;
    struct kobject *root_kobject = NULL;
    char name[16];
    int s = 0;
    pid_t pid = 0;

    // Sanity checks 
    if(0 > idx || idx >= MONMOD_MAX_N_TRACEES) {
        return 1;
    }
    root_kobject = &monmod_global_config.kobj;
    config_kobject = &monmod_global_config.tracees[idx].kobj;
    pid = monmod_global_config.tracee_pids[idx];

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

void monmod_tracee_config_free(size_t idx)
{
    // Sanity checks
    if(0 > idx || idx >= MONMOD_MAX_N_TRACEES) {
        return;
    }
    kobject_put(&monmod_global_config.tracees[idx].kobj);
}

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


// Generic callbacks

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

// Specific setting callbacks


CONFIG_LONG_SHOW_FUN(trusted_addr, struct monmod_tracee_config, trusted_addr)
CONFIG_LONG_STORE_FUN(trusted_addr, struct monmod_tracee_config, trusted_addr, 
                      true)

CONFIG_LONG_SHOW_FUN(trace_func_addr, struct monmod_tracee_config, 
                     trace_func_addr)
CONFIG_LONG_STORE_FUN(trace_func_addr, struct monmod_tracee_config, 
                      trace_func_addr, true)

CONFIG_LONG_SHOW_FUN(active, struct monmod_config, active)
CONFIG_LONG_STORE_FUN(active, struct monmod_config, active, false)

/*

struct monmod_config *dst = container_of(kobject, struct monmod_config, kobj); 
const struct kobject * *__mptr = (ptr);	
*/

ssize_t _monmod_config_tracee_pids_show(struct kobject *kobject, 
                                        struct kobj_attribute *attr,
                                        char *buf)
{
    size_t n_written = 0;
    size_t i = 0;
    if(0 != _config_callback_sanity_checks(kobject, attr, buf)) {
        return -1;
    }
    for(i = 0; i < MONMOD_MAX_N_TRACEES; i++) {
        if(0 == monmod_global_config.tracee_pids[i]) {
            continue;
        }
        n_written += snprintf(buf + n_written, PAGE_SIZE - n_written,
                              "%d\n", monmod_global_config.tracee_pids[i]);
    }
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
#define array_contains(haystack, max_len, needle) ({\
    int i = 0; \
    bool result = false; \
    for(; i < max_len && 0 != haystack[i]; i++) { \
        if(haystack[i] == needle) { \
            result = true; \
            break; \
        } \
    } \
    result; \
})

    size_t consumed = 0;
    size_t n_old_pids = 0;
    size_t n_new_pids = 0;
    pid_t old_pids[MONMOD_MAX_N_TRACEES];
    pid_t new_pids[MONMOD_MAX_N_TRACEES];
    int i = 0;
    if(0 != _config_callback_sanity_checks(kobj, attr, buf)) {
        return -1;
    }

    // Save old pids
    memcpy(old_pids, monmod_global_config.tracee_pids, sizeof(old_pids));
    n_old_pids = monmod_global_config.n_tracees;

    // Scan input
    while(consumed < count) {
        pid_t pid = 0;
        ssize_t line_len = next_int_line(buf + consumed, count - consumed, 
                                         &pid);
        if(line_len < 0) { // Invalid input encountered.
            MONMOD_WARNF("Parsing configuration: Invalid input at offset %lu", 
                         consumed);
            return -1;
        }
        if(line_len == 0) { // No input numbers remaining; everything was valid.
            consumed = count;
            break;
        }
        if(n_new_pids >= MONMOD_MAX_N_TRACEES) {
            MONMOD_WARNF("Parsing configuration: More than %d tracees are not "
                         "supported.\n", MONMOD_MAX_N_TRACEES);
            return -1;
        }
        new_pids[n_new_pids] = pid;
        n_new_pids += 1;
        consumed += line_len;
    }

    // See what has changed
    for(i = 0; i < n_old_pids; i++) {
        pid_t pid = old_pids[i];
        if(!array_contains(new_pids, n_new_pids, pid)) {
            if(0 == monmod_del_tracee_config(i)) {
                printk(KERN_INFO "monmod: Removed tracing for PID %d.\n", pid);
            } else {
                printk(KERN_INFO "monmod: Failed to remove tracing for PID "
                       "%d.\n", pid);
                return -1;
            }
        }
    }
    for(i = 0; i < n_new_pids; i++) {
        pid_t pid = new_pids[i];
        if(!array_contains(old_pids, n_old_pids, pid)) {
            if(0 == monmod_add_tracee_config(pid)) {
                printk(KERN_INFO "monmod: Added tracing for PID %d.\n", pid);
            } else {
                printk(KERN_INFO "monmod: Failed to add tracing for PID %d.\n",
                       pid);
                return -1;
            }
        }
    }

    return consumed;

#undef array_contains
}

ssize_t _monmod_config_tracee_pids_add_show(struct kobject *kobject, 
                                        struct kobj_attribute *attr,
                                        char *buf)
{
    const char msg[] = "Refer to /sys/kernel/monmod/tracee_pids.\n"
                       "Writing to this file will add a single PID.\n";
    memcpy(buf, msg, sizeof(msg));
    return sizeof(msg);
}

ssize_t _monmod_config_tracee_pids_add_store(struct kobject *kobject, 
                                             struct kobj_attribute *attr,
                                             const char *buf,
                                             size_t count)
{
    pid_t pid = 0;
    size_t line_len = 0;
    if(0 != _config_callback_sanity_checks(kobject, attr, buf)) {
        return -1;
    }
    if(monmod_global_config.n_tracees >= MONMOD_MAX_N_TRACEES) {
        return -1;
    }
    line_len = next_int_line(buf, count, &pid);
    if(line_len < 0) {
        printk(KERN_INFO "monmod: Invalid input, or more than one line.\n");
        return -1;
    }
    if(monmod_is_pid_traced(pid)) {
        printk(KERN_INFO "monmod: PID %d is already being traced.\n", pid);
        return -1;
    }
    if(0 == monmod_add_tracee_config(pid)) {
        printk(KERN_INFO "monmod: Added tracing for PID %d.\n", pid);
    } else {
        printk(KERN_INFO "monmod: Failed to add tracing for PID %d.\n",
                pid);
        return -1;
    }
    return count;
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
