
#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "monitor.h"
#include "syscall_trace_func.h"
#include "util.h"
#include "handlers.h"
#include "policy.h"
#include "globals.h"
#include "arch.h"
#include "unprotected.h"
#include "exchanges.h"
#include "communication.h"
#include "library_init.h"


/* ************************************************************************** *
 * Global Variables                                                           *
 * ************************************************************************** */

#if !MEASURE_TRACING_OVERHEAD
__attribute__((section("protected_state")))
#endif
struct monitor monitor;

#if ENABLE_CHECKPOINTING
// Needs to be in unprotected section.
struct checkpoint_env checkpoint_env;
#endif


/* ************************************************************************** *
 * Local Variables                                                            *
 * ************************************************************************** */

char syscall_log_buf[1024];
bool is_exiting = false;


/* ************************************************************************** *
 * Local Forward Declarations                                                 *
 * ************************************************************************** */

static int
syscall_dispatch_apply_policy(int dispatch, struct syscall_info *canonical,
                              struct policy *policy);
static int
syscall_check_dispatch_sanity(int dispatch,
                              struct syscall_handler const *const handler,
                              struct syscall_info *actual,
                              struct syscall_info *canonical);

static void syscall_execute_locally(struct syscall_handler const *const handler,
                                    struct syscall_info *actual, 
                                    struct syscall_info *canonical);

static int handle_error(const struct monitor * const monitor);

static int handle_divergence(const struct monitor * const monitor);

#if !NO_HEADERS
static int handle_message_divergence(const struct communicator *comm,
                                     const struct peer *peer,
	                                 const struct message_header *msg,
                                     comm_header_t short_header_expected);
#endif

static void
handle_cross_check_divergence(const struct monitor * const monitor,
                              const struct syscall_handler * const handler,
                              struct syscall_info *actual,
                              struct syscall_info *canonical,
                              const void *ret_addr);

static void terminate(struct monitor * const monitor);


/* ************************************************************************** *
 * System Call Monitoring                                                     *
 * ************************************************************************** */

/* All monitored system calls go through this function, registered with the
   monmod_init system call. */
long monmod_handle_syscall(struct syscall_trace_func_stack * const stack)
{
	//test(&monitor.comm);
#if MEASURE_TRACING_OVERHEAD
	return monmod_trusted_syscall(SYSCALL_NO_REG(&stack->regs), 
           SYSCALL_ARG0_REG(&stack->regs), SYSCALL_ARG1_REG(&stack->regs), 
           SYSCALL_ARG2_REG(&stack->regs), SYSCALL_ARG3_REG(&stack->regs), 
           SYSCALL_ARG4_REG(&stack->regs), SYSCALL_ARG5_REG(&stack->regs));
#else

	if(is_exiting) {
		terminate(&monitor);
	}

	int s = 0;
	struct pt_regs * const regs = &(stack->regs);

#if ENABLE_CHECKPOINTING
	const double r = monitor_random(&monitor);
	if(monitor.checkpoint_env->last_checkpoint.valid) {
		if(monitor.is_leader && r < monitor.conf.restore_probability) {
	#if VERBOSITY >= 2
			SAFE_LOGF("Leader inducing fake error (r=%f).\n", r);
	#endif
			SAFE_NZ_TRY(synchronize(&monitor, exchange_fake_error));
		}
		/* Cause an artificial divergence probabilistically to test system if
		so configured. We only inject faults once the first checkpoint has
		been created -- thus assuming that the checkpoints are reasonably
		set, before any exposed code runs. */
		if(r < monitor.conf.inject_fault_probability) {
	#if VERBOSITY >= 2
			SAFE_LOGF("Variant %d inducing fake divergence: Replacing syscall "
					"%ld with -1 (random %f).\n", 
					monitor.own_id, SYSCALL_NO_REG(regs), r);
	#endif
			SYSCALL_NO_REG(regs) = -1;
		}
	}
#endif

	const long syscall_no = SYSCALL_NO_REG(regs);
	const void *ret_addr = (void *)PC_REG(regs);
	struct syscall_handler const * const handler = get_handler(syscall_no);
	struct syscall_info actual = {};
	struct syscall_info canonical = {};
	void *handler_scratch_space = NULL;
	int dispatch = 0;

#if VERBOSITY >= 2
	struct timeval tv, rel_tv;
#endif

#if ENABLE_CHECKPOINTING
	syscall_handle_checkpointing(monitor.checkpoint_env);
#endif
#if NO_HANDLER_TERMINATES
	if(NULL == handler) {
		SAFE_WARNF("No handler for system call %ld.\n", syscall_no);
		exit(1);
	}
#endif

	/* Preparation: Initialize data structures. */
	actual.no = syscall_no;
	SYSCALL_ARGS_TO_ARRAY(regs, actual.args);
	actual.ret = -ENOSYS;
	canonical.no = syscall_no;
	if(NULL != handler) {
		canonical.no = handler->canonical_no;
	}
	SYSCALL_ARGS_TO_ARRAY(regs, canonical.args);  
		// will probably be modified

	/* Phase 1: Determine call dispatch type through entry handler. */
#if VERBOSITY >= 2
	SAFE_LZ_TRY(gettimeofday(&tv, NULL));
	timersub(&tv, &monitor.start_tv, &rel_tv);
	if(NULL != handler) {
		SAFE_LOGF("[%3ld.%06ld] >> %s (%ld) -- enter from PC %p, PID "
			  "%d.\n", rel_tv.tv_sec, rel_tv.tv_usec,
			  handler->name, actual.no, ret_addr,
			  monitor.env.pid->local_pid);
	} else {
		SAFE_LOGF("[%3ld.%06ld] >> enter unhandled syscall %ld.\n",
		          rel_tv.tv_sec, rel_tv.tv_usec, actual.no);
	}
#endif
	dispatch = DISPATCH_UNCHECKED | DISPATCH_EVERYONE;	
	if(NULL != handler && NULL != handler->enter) {
		dispatch = handler->enter(&monitor.env, handler, &actual, 
		                          &canonical, &handler_scratch_space);
	}
	if(policy_is_exempt(monitor.policy, &canonical, &monitor.env)) {
#if VERBOSITY >= 3
		SAFE_LOGF("Policy \"%s\" exempted system call from "
		          "cross-checking.\n", monitor.policy->name);
#endif
		dispatch &= ~DISPATCH_CHECKED & ~DISPATCH_DEFERRED_CHECK;
		dispatch |= DISPATCH_UNCHECKED;
	}

	if(dispatch & DISPATCH_ERROR) {
		SAFE_WARN("Dispatch error.\n");
		SAFE_NZ_TRY(synchronize(&monitor, exchange_error));
		monmod_exit(1);
	}

	syscall_check_dispatch_sanity(dispatch, handler, &actual, &canonical);

	/* Phase 2: Cross-check system call & arguments with other variants. */
	if(dispatch & (DISPATCH_CHECKED | DISPATCH_DEFERRED_CHECK)) {
		SAFE_LZ_TRY_EXCEPT(s = cross_check_args(&monitor, &canonical),
		                   synchronize(&monitor, exchange_error));
		if(0 == s) {
			handle_cross_check_divergence(&monitor, handler, 
			                              &actual, &canonical, 
			                              ret_addr);
		}
	}

	/* Phase 3: Execute system call locally if needed. */
	if(dispatch & DISPATCH_EVERYONE || 
	   ((dispatch & DISPATCH_LEADER) && monitor.is_leader)) {
		syscall_execute_locally(handler, &actual, &canonical);
		if(NULL != handler && NULL != handler->post_call) {
			/* This callback gets called whenever a system call has
			   actually been issued locally. It can be used to
			   normalize results in a canonical form before 
			   replication, from actual into canonical. */
			handler->post_call(&monitor.env, handler, dispatch, 
			                   &actual, &canonical, 
			                   &handler_scratch_space);
		}
	}

	if(dispatch & DISPATCH_NEEDS_REPLICATION) {
		/* Replicates contents of canonical.ret and canonical.args to 
		   be the same across all nodes. It is the exit handler's 
		   responsibility to copy this back to the actual results as
		   appropriate. */
		s = replicate_results(&monitor, &canonical);
		if(0 != s) {
#if VERBOSITY >= 2
			SAFE_WARN("Divergence or error occured during replication.\n");
#endif
			SAFE_NZ_TRY(synchronize(&monitor, exchange_recoverable_error));
			monmod_exit(1);
		}
	}

	/* Phase 4: Run exit handlers, potentially denormalizing results. */
	if(NULL != handler && NULL != handler->exit 
	   && !(dispatch & DISPATCH_SKIP)) {
		s = handler->exit(&monitor.env, handler, dispatch, &actual, 
		                  &canonical, &handler_scratch_space);
		if(0 != s) {
			SAFE_WARNF("Exit handler returned error %d.\n", s);
			SAFE_NZ_TRY(synchronize(&monitor, exchange_error));
			monmod_exit(1);
		}
	}

#if VERBOSITY >= 2
	SAFE_LZ_TRY(gettimeofday(&tv, NULL));
	timersub(&tv, &monitor.start_tv, &rel_tv);
	SAFE_LOGF("[%3ld.%06ld] << Return %ld.\n\n", rel_tv.tv_sec, 
	          rel_tv.tv_usec, actual.ret);
#endif

	return actual.ret;
#endif
}

static int
syscall_check_dispatch_sanity(int dispatch,
                              struct syscall_handler const *const handler,
                              struct syscall_info *actual,
                              struct syscall_info *canonical)
{
	if(dispatch & DISPATCH_LEADER) {
		if(!(dispatch & DISPATCH_NEEDS_REPLICATION)) {
#if VERBOSITY >= 2
			SAFE_WARN("Warning: Syscall dispatched only on leader, "
			          "but no replication flag set.\n"); 
#endif
			return 1;
		}
		if(!(canonical->ret_flags & ARG_FLAG_REPLICATE)) {
#if VERBOSITY >= 2
			SAFE_WARN("Warning: Syscall dispatched only on leader, "
			          "but no replication flag set for return "
				  "value. This is probably not what you "
				  "want.\n");
#endif
			return 1;
		}
	}

#if VERBOSITY >= 4
	if(NULL != handler) {
		syscall_log_buf[0] = '\0';
		log_args(syscall_log_buf, sizeof(syscall_log_buf), actual, 
		         canonical);
		SAFE_LOGF_LEN(sizeof(syscall_log_buf), "%s", 
		              syscall_log_buf);
	}
#endif

	return 0;
}

static void syscall_execute_locally(struct syscall_handler const *const handler,
                                    struct syscall_info *actual, 
                                    struct syscall_info *canonical)
{
#if VERBOSITY >= 4
	SAFE_LOGF("Executing syscall no. %ld with (%ld, %ld, %ld, %ld, "
	          "%ld, %ld)\n",
		  actual->no, actual->args[0], actual->args[1],
		  actual->args[2], actual->args[3], actual->args[4],
		  actual->args[5]);
#endif
	actual->ret = monmod_trusted_syscall(actual->no, 
	                                     actual->args[0], 
	                                     actual->args[1],
	                                     actual->args[2],
	                                     actual->args[3],
	                                     actual->args[4], 
	                                     actual->args[5]);
	canonical->ret = actual->ret;  // Default to the same

#if VERBOSITY >= 4
		if(-1024 < actual->ret && actual->ret < 0) {
			SAFE_LOGF("Returned: %ld (potential errno: %s)\n", 
			          actual->ret, strerror(-actual->ret));
		} else {
			SAFE_LOGF("Returned: %ld\n", actual->ret);
		}
#endif
}


/* ************************************************************************** *
 * Divergence Handling                                                        *
 * ************************************************************************** */

static int handle_error(const struct monitor * const monitor)
{
	SAFE_WARN("Terminating due to error in all variants.\n");
	monmod_exit(2);
}

static int handle_divergence(const struct monitor * const monitor)
{
	int s = 0;
#if ENABLE_CHECKPOINTING
	if(monitor->checkpoint_env->last_checkpoint.valid) {
		s = restore_last_checkpoint(monitor->checkpoint_env);
		if(0 != s) {
			SAFE_WARNF("Checkpoint restoration failed with "
			          "exit code %d.\n", s);
		}
	} else {
		SAFE_WARN("No valid last checkpoint.\n");
	}
#endif
	monmod_exit(2);
}

#if !NO_HEADERS
static int handle_message_divergence(const struct communicator *comm,
                                     const struct peer *peer,
	                                 const struct message_header *msg,
                                     comm_header_t short_header_expected)
{
	const comm_header_t short_header_actual = msg->header;
	const msg_type_t header_actual = (msg_type_t)short_header_actual;
	const msg_type_t header_expected = (msg_type_t)short_header_expected;
	size_t n = 0;
#if VERBOSITY > 1
	if(header_actual != header_expected) {
		SAFE_LOGF("Diverging message headers. "
                  "Actual: (%d) %s. "
                  "Expected: (%d) %s.\n", 
                  header_actual, msg_type_str(header_actual),
                  header_expected, msg_type_str(header_expected));
	}
#endif
    if(header_actual != header_expected 
	   || exchange_fake_error == header_actual
	   || exchange_recoverable_error == header_actual) {
		// Throw away rest of message, if any.
		comm_receive_body(comm, peer, msg, &n, NULL);
        return handle_divergence(&monitor);
    } else if(header_actual == header_expected 
	          && exchange_error == header_actual) {
		// Throw away rest of message, if any.
		comm_receive_body(comm, peer, msg, &n, NULL);
        return handle_error(&monitor);
    }
    return 0;
}
#endif

static
void handle_cross_check_divergence(const struct monitor * const monitor,
                                   struct syscall_handler const *const handler,
                                   struct syscall_info *actual,
                                   struct syscall_info *canonical,
                                   const void * ret_addr)
{
	struct timeval tv, rel_tv;
	SAFE_LZ_TRY(gettimeofday(&tv, NULL));
	timersub(&tv, &monitor->start_tv, &rel_tv);
#if !ENABLE_CHECKPOINTING
	SAFE_LOGF("[%3ld.%06ld] Divergence in '%s' called from %p, PID %d "
	          "-- abort!\n", rel_tv.tv_sec, rel_tv.tv_usec, handler->name, 
		  ret_addr, monitor->env.pid->local_pid);
#else
	SAFE_LOGF("[%3ld.%06ld] Divergence in '%s' called from %p, PID %d "
	          "-- attempting to restore last checkpoint.\n",
		  rel_tv.tv_sec, rel_tv.tv_usec, handler->name, ret_addr,
		  monitor->env.pid->local_pid);
#endif
#if VERBOSITY > 0 && VERBOSITY < 3
	// Print divergence information if we have not before.
	if(NULL != handler) {
		SAFE_LOGF("%s (%ld)\n", handler->name, actual->no);
		char log_buf[1024];
		log_buf[0] = '\0';
		log_args(log_buf, sizeof(log_buf), actual, canonical);
		SAFE_LOGF_LEN(sizeof(log_buf), "%s", log_buf);
	}
#endif
	handle_divergence(monitor);
}


/* ************************************************************************** *
 * Initialization                                                             *
 * ************************************************************************** */

void register_monitor_in_kernel(struct monitor *monitor) {
	char *start = NULL, 
	     *code_start = NULL, 
	     *protected_data_start = NULL; 
	size_t len = 0,
	       code_len = 0, 
	       protected_code_len = 0,
	       protected_data_len = 0;
	

	/* Find the pages this module is loaded on. These pages will be 
	   protected by the kernel to remain inaccessible for other parts of
	   the program. */
	SAFE_NZ_TRY(find_mapped_region_bounds(&monmod_library_init, 
	                                      (void **)&code_start, 
	                                      &code_len));
	
	start = code_start;
	len = &__monitor_end - start;

	protected_code_len = &__unprotected_start - code_start;
	protected_data_start = &__protected_state_start;
	protected_data_len = &__protected_state_end - protected_data_start;

	/* Sanity check that our linker script worked and, after loading,
	   the "unprotected" section is the very last page-aligned sub-section
	   of the loaded executable segment. */
	SAFE_Z_TRY(code_len == (code_len & ~(monmod_page_size-1))
	           && &__unprotected_end == code_start + code_len
	           && &__unprotected_start > code_start 
	           && &__unprotected_start < code_start + code_len
	           && protected_data_len > 0
	           && len > 0 
	           && start < protected_data_start
	           && protected_data_start + protected_data_len < start + len);
	
#if VERBOSITY >= 1
	SAFE_LOGF("Initializing monmod tracing with %lu bytes of protected data.\n",
	          protected_data_len);
#endif
	SAFE_NZ_TRY(monmod_init(monitor->env.pid->local_pid, 
	                        &monmod_syscall_trusted_addr,
	                        &monmod_syscall_trace_enter,
	                        start, len,
	                        code_start, protected_code_len,
	                        protected_data_start, protected_data_len));

#if ENABLE_CHECKPOINTING
	monitor->addr_ranges = (struct monmod_monitor_addr_ranges) {
		.overall_start = start,
		.overall_len = len,
		.code_start = code_start,
		.code_len = protected_code_len,
		.protected_data_start = protected_data_start,
		.protected_data_len = protected_data_len
	};
#endif
}

int monitor_init_comm(struct communicator *comm, struct config *conf, int id)
{
	struct variant_config *own_variant_conf;
	SAFE_Z_TRY(own_variant_conf = get_variant(conf, id));
	SAFE_LZ_TRY(comm_init(comm, id, &own_variant_conf->addr));
#if !NO_HEADERS
	comm_set_outbound_header(comm, exchange_init);
	comm_set_check_header_func(comm, handle_message_divergence);
#endif
	for(size_t i = 0; i < conf->n_variants; i++) {
		if(conf->variants[i].id == id) {
			continue;
		}
		SAFE_NZ_TRY(comm_connect(comm, conf->variants[i].id, 
		                         &conf->variants[i].addr));
	}
	return 0;
}

int monitor_init(struct monitor *monitor, int own_id, struct config *conf)
{
	struct variant_config *own_variant_conf;

	memset(monitor, 0, sizeof(monitor));

	monitor->own_id = own_id;
	monitor->leader_id = conf->leader_id;
	monitor->is_leader = conf->leader_id == own_id;
	monitor->conf = *conf;
	monitor->ancestry = 0;
	SAFE_Z_TRY(monitor->policy = policy_from_str(conf->policy));

	SAFE_Z_TRY(own_variant_conf = get_variant(conf, own_id));

	/* Connect everyone to everyone. */
	SAFE_NZ_TRY(monitor_init_comm(&monitor->comm, &monitor->conf, 
	                              monitor->own_id));

	SAFE_NZ_TRY(env_init(&monitor->env, monitor->is_leader));

	/* Checkpointing */
#if ENABLE_CHECKPOINTING
	/* The checkpointing environment needs to be initialized before 
	   the monitor is registered: CRIU checkpointing forks a new
	   dumper/restorer parent process, and the child process is the one
	   that should register to be monitored. */
	monitor->checkpoint_env = &checkpoint_env;
	SAFE_NZ_TRY(init_checkpoint_env(&checkpoint_env,
	                                monitor,
	                                &monitor->env,
	                                own_variant_conf,
					&monitor->addr_ranges));
	monitor->env.pid->local_pid = getpid();
#endif

	/* Initialize Individual Basic Monitoring Components */
#if MEASURE_TRACING_OVERHEAD
	/* If we are only interested in measuring the tracing overhead, register
	   the monitor now and exit, before setting up any of the network
	   connections or checkpointing environment. */
	register_monitor_in_kernel(monitor);
	return 0;
#endif

	SAFE_NZ_TRY(replication_init(monitor, conf->replication_batch_size));

	/* Initiate random number generator used for fault injection */
	monitor_init_random(monitor, 0);

	/* -- Register Tracing With Kernel Module -- */
	register_monitor_in_kernel(monitor);

#if VERBOSITY >= 1
	SAFE_LZ_TRY(gettimeofday(&monitor->start_tv, NULL));
	SAFE_LOGF("Starting monitored execution of process %d.\n",
	          monitor->env.pid->local_pid);
#endif

	return 0;
}

void 
__attribute__((destructor)) 
__attribute__((section("unprotected")))
monmod_library_destroy()
{
	is_exiting = true;
	unprotected_funcs.exit(0);  /* any system call that gets us into
	                               monmod_handle_syscall will do here. */
}

static void terminate(struct monitor * const monitor)
{
	struct timeval end_tv, duration;
	synchronize(monitor, exchange_terminate);
	replication_destroy(monitor);
	comm_destroy(&monitor->comm);
#if VERBOSITY >= 1
	SAFE_NZ_TRY(gettimeofday(&end_tv, NULL));
	timersub(&end_tv, &monitor->start_tv, &duration);
	SAFE_LOGF("Terminated after %ld.%06ld seconds.\n",
	          duration.tv_sec, duration.tv_usec);
#endif
	close(monmod_log_fd);
	/* Nothing may run after our monitor is destroyed. Without this,
	   exit code may flush buffers etc without us monitoring this.
	   FIXME always exits with zero exit code */
	exit(0);
}


/* ************************************************************************** *
 * Monitor Cloning                                                            *
 * ************************************************************************** */

int monitor_arbitrate_child_comm(struct monitor *parent_monitor,
                                 struct communicator *child_comm);

int monitor_child_fix_up(struct monitor *monitor,
                         struct communicator *child_comm)
{
	// Open a new log file for this child.
	close(monmod_log_fd);
	NZ_TRY_EXCEPT(open_log_file(monitor->own_id, monitor->ancestry), 
	              exit(0));

	// Adjust PIDs.
	SAFE_Z_TRY(monitor->env.ppid = monitor->env.pid);
	SAFE_Z_TRY(monitor->env.pid = 
	           env_add_local_pid_info(&monitor->env, getpid()));
#if !USE_LIBVMA
	SAFE_NZ_TRY(comm_destroy(&monitor->comm));
#endif
	monitor->comm = *child_comm;

	monitor_init_random(monitor, 0);
	
	/* Register tracing in new child. */
	register_monitor_in_kernel(monitor);

	return 0;
}

int monitor_arbitrate_child_comm(struct monitor *parent_monitor,
                                 struct communicator *child_comm)
{
#if USE_LIBVMA == USE_LIBVMA_LOCAL
	const in_port_t hard_port_offset = 10;
#endif
	struct arbitration_msg {
		uint64_t n_variants;
		uint64_t variant_ports[];
	};

	/* Everyone starts a new server. */
	struct sockaddr_in own_addr = { .sin_family = AF_INET,
	                                .sin_addr = INADDR_ANY,
					.sin_port = 0 };
#if USE_LIBVMA == USE_LIBVMA_LOCAL
	/* libVMA does not persist open sockets across fork, so above approach
	    of opening the child socket before the fork to obtain any open
	    port does not work.
	    
	    Instead, when libVMA is used, this function is actually called
	    _after_ the fork already took place, and we use hard coded ports
	    instead. */
	close(parent_monitor->comm.self.fd);
	in_port_t own_hard_port = 
		htons(ntohs(((struct sockaddr_in *)&parent_monitor
		                                   ->comm.self.addr)->sin_port)
		      + hard_port_offset);
	own_addr.sin_port = own_hard_port;
#endif

	uint64_t own_port;
	SAFE_LZ_TRY(own_port = comm_init(child_comm, 
	                                 parent_monitor->own_id, 
	                                 (struct sockaddr *)&own_addr));
#if !NO_HEADERS
	comm_set_outbound_header(child_comm, exchange_init);
	comm_set_check_header_func(child_comm, handle_message_divergence);
#endif
	own_port = htons(own_port);
	uint64_t variant_ports[parent_monitor->conf.n_variants];

#if USE_LIBVMA != USE_LIBVMA_LOCAL
	/* Exchange open port information for the child communicator. */

	SAFE_NZ_TRY(synchronize(parent_monitor, exchange_fork));

	/* We let everyone know the new ports for the servers we just 
	   started using the existing parent connection. */
	if(!parent_monitor->is_leader) {
		/* Everyone but the leader tells the leader their new server's 
		   port. */
		size_t outbound_sz = sizeof(struct arbitration_msg)
		                     + sizeof(uint64_t);
		char outbound_buf[outbound_sz];
		struct arbitration_msg *outbound = 
			(struct arbitration_msg *)outbound_buf;
		size_t received_sz = sizeof(struct arbitration_msg)
		                     + parent_monitor->conf.n_variants 
				       * sizeof(uint64_t);
		char received_buf[received_sz];
		struct arbitration_msg *received = 
			(struct arbitration_msg *)received_buf;
		outbound->n_variants = 1;
		outbound->variant_ports[0] = (uint64_t)own_port;
		SAFE_NZ_TRY(comm_send(&parent_monitor->comm, 
		                      parent_monitor->leader_id,
		                      outbound_sz, outbound_buf));
		SAFE_NZ_TRY(comm_receive(&parent_monitor->comm, 
		                         parent_monitor->leader_id,
		                         &received_sz, received_buf));
		// Sanity checks
		SAFE_Z_TRY(received_sz == sizeof(received_buf)
		           && received->n_variants 
			      == parent_monitor->conf.n_variants);
		memcpy(variant_ports, received->variant_ports,
		       sizeof(variant_ports));
	} else {
		/* The leader broadcasts the set of new ports.*/
		size_t received_sz = sizeof(struct arbitration_msg)
		                     + sizeof(uint64_t);
		char received_buf[received_sz];
		struct arbitration_msg *received =
			(struct arbitration_msg *)received_buf;
		size_t outbound_sz = sizeof(struct arbitration_msg)
		                     + parent_monitor->conf.n_variants
				       * sizeof(uint64_t);
		char outbound_buf[outbound_sz];
		struct arbitration_msg *outbound =
			(struct arbitration_msg *)outbound_buf;
		outbound->n_variants = parent_monitor->conf.n_variants;
		for(int i = 0; i < parent_monitor->conf.n_variants; i++) {
			int id = parent_monitor->conf.variants[i].id;
			if(id == parent_monitor->leader_id) {
				outbound->variant_ports[i] = own_port;
			} else {
				SAFE_NZ_TRY(comm_receive(&parent_monitor->comm,
				                         id, &received_sz,
							 received_buf));
				// Sanity checks
				SAFE_Z_TRY(received->n_variants == 1 &&
				           received_sz == sizeof(received_buf));
				outbound->variant_ports[i] =
					received->variant_ports[0];
			}
		}
		SAFE_NZ_TRY(comm_broadcast(&parent_monitor->comm, outbound_sz,
		                           outbound_buf));
		memcpy(variant_ports, outbound->variant_ports,
		       sizeof(variant_ports));
	}
#else
	/* Use hard-coded ports if we are using libVMA. */
	for(size_t i = 0; i < parent_monitor->conf.n_variants; i++) {
		const in_port_t hard_port = 
			htons(ntohs(((struct sockaddr_in *)&parent_monitor
			             ->conf.variants[i].addr)->sin_port)
			      + hard_port_offset);
		variant_ports[i] = hard_port;
	}
#endif

	/* Finally, connect everyone to everyone on the new negotiated ports. */
	for(size_t i = 0; i < parent_monitor->conf.n_variants; i++) {
		struct sockaddr_in child_addr =  {};
		if(parent_monitor->conf.variants[i].id 
		   == parent_monitor->own_id) {
			continue;
		}
		child_addr.sin_family = AF_INET;
		child_addr.sin_addr = 
			((struct sockaddr_in *)&parent_monitor
			                       ->conf.variants[i].addr)
			->sin_addr;
		child_addr.sin_port = variant_ports[i];
#if USE_LIBVMA == USE_LIBVMA_LOCAL
		usleep(200000*parent_monitor->own_id);
			/* ... if you have a better idea, I'm all ears. We are
			   in the child process and cannot use parents socket
			   to synchronize. */
#endif
		SAFE_NZ_TRY(comm_connect(child_comm, 
		                    parent_monitor->conf.variants[i].id, 
		                    (struct sockaddr *)&child_addr));
	}
	return 0;
}
