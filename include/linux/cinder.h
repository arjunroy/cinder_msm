#ifndef __LINUX_CINDER_H__
#define __LINUX_CINDER_H__

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#define CINDER_MAX_NAMELEN 20

#define CINDER_CAP_RESERVE_DRAW   0x1
#define CINDER_CAP_RESERVE_MODIFY 0x2
#define CINDER_CAP_ALL (CINDER_CAP_RESERVE_DRAW | CINDER_CAP_RESERVE_MODIFY)

#define CINDER_TAP_RATE_CONSTANT 1
#define CINDER_TAP_RATE_PROPORTIONAL 2

#define CINDER_TAP_THREAD_SLEEPTIME 500
#define CINDER_TAP_DRAW_INTERVAL_MS 1000

#define CINDER_RESERVE_MIN_VALID 1

struct task_struct;
struct cinder_tap;
struct cinder_reserve;
struct cinder_reserve_process_link;

extern struct cinder_reserve root_reserve;
extern struct cinder_reserve_process_link init_root_link;

// TODO: Temporary hack
extern int cinder_ready;
extern spinlock_t cinder_ready_lock;

long timespec_to_ms(struct timespec *ts);
long cinder_cpu_draw_rate_per_second(void);

/* Battery methods are implemented in an arch-specific manner */
long cinder_max_battery_level(void); /* microAH */
long cinder_current_battery_level(void); /* % value*/
long cinder_is_plugged_in(void);
long cinder_battery_root_sync(void);

/* Initial Cinder setup */
void cinder_setup(struct task_struct *swapper_task);

/* Setup/cleanup reserve/taps */
int cinder_setup_reserve(struct cinder_reserve *reserve, const char *name);
void cinder_cleanup_reserve(struct cinder_reserve *reserve);
void cinder_remove_reserve_taps(struct cinder_reserve_process_link *link);
void cinder_detach_link_from_process(struct cinder_reserve_process_link *link);
void cinder_detach_link_from_reserve(struct cinder_reserve_process_link *link);
void cinder_remove_tap(struct cinder_tap *tap);

/* Setup/cleanup task */
void cinder_setup_task_common(struct task_struct *tsk);
void cinder_cleanup_task(struct task_struct *tsk);
int cinder_setup_forked_thread(struct task_struct *thread, struct task_struct *parent);

/* Setup/cleanup process<->reserve link */
void cinder_connect_link_to_reserve(struct cinder_reserve_process_link *link,
				    struct cinder_reserve *reserve,
				    unsigned int capabilities);
void cinder_connect_link_to_process(struct cinder_reserve_process_link *link,
				    struct task_struct *tsk);
void cinder_setup_reserve_link(struct cinder_reserve_process_link *link,
			       struct cinder_reserve_process_link *child_link,
			       struct task_struct *tsk,
			       struct cinder_reserve *reserve,
			       unsigned int capabilities);
void cinder_cleanup_reserve_link(struct cinder_reserve_process_link *link);
void cinder_cleanup_reserve_links(struct task_struct *tsk);
void cinder_cleanup_child_reserve_links(struct task_struct *tsk, struct task_struct *group_leader);
void cinder_add_reserve_to_child_list(struct cinder_reserve_process_link *link,
				      struct cinder_reserve_process_link *clink,
				      struct task_struct *tsk,
				      struct task_struct *group_leader, 
				      unsigned int capabilities);
void cinder_remove_reserve_from_child_lists(long reserve_id, struct task_struct *group_leader);
int cinder_remove_reserve_from_child_list_by_id(long reserve_id, struct task_struct *tsk);

int cinder_cleanup_tsk_netdev_acct(struct task_struct *tsk);

/* Setup reserve links for kthreads and processes */
int cinder_setup_child_reserves(struct task_struct *child, struct task_struct *parent);
int cinder_setup_kthread_reserve(struct task_struct *tsk);

/* Kernel thread for updating taps */
int cinder_tap_daemon(void * unused);

struct cinder_reserve {
	int id;

	long capacity;
	struct list_head taps_to;
	struct list_head taps_from;

	/* Accessible in some way by process */
	struct list_head process_links;

	char name[CINDER_MAX_NAMELEN];
	
	/* Each reserve has a single spinlock for all of its fields */
	spinlock_t reserve_lock;
	atomic_t refcount;

	/* Fields for tap accounting*/
	struct list_head global_list;
	long value_to_add;

};

struct cinder_reserve_process_link {
	struct list_head process_list;
	struct list_head reserve_list;

	struct task_struct *process;
	struct task_struct *thread;
	struct cinder_reserve *reserve;

	unsigned int capabilities;
};

struct cinder_tap {
	int id;
	long rate;
	unsigned long type;

	spinlock_t tap_lock;

	struct cinder_reserve *src_reserve;
	struct cinder_reserve *dest_reserve;

	struct list_head reserve_to;
	struct list_head reserve_from;
	struct list_head process_list;

	char name[CINDER_MAX_NAMELEN];

	struct task_struct *creator;
	/* Tap locking handled by cinder_lock for process */

	/* Used by tap adjuster thread __only__ */
	long draw_amount;
	long time_of_last_flow;
};

#else

#endif /* ifdef __KERNEL__ */

struct reserve_info {
	int id;
	long capacity;
	char name[CINDER_MAX_NAMELEN];
	
	/* TODO: Implement # taps */
	int num_process_taps;
};

struct tap_info {
	int id;
	long rate;
	unsigned long type;

	long reserve_to;
	long reserve_from;

	char name[CINDER_MAX_NAMELEN];
	pid_t creator;
};

#endif /* ifndef __LINUX_CINDER_H__ */

/*
Kthread : ktapd

Battery holds charge in milliamp-hours
Battery also gives us voltage info along with charge. So we can calculate the
instantaneous power as being V * I, and then time delta can give us an estimate
for the energy used.

*/

/*
Delegation

The simplest thing that makes sense is to have a delegation specific reserve per
process. It should last the lifetime of the entire process, should not be 'puttable',
and the existence of such a reserve is assumed for each process (though others cannot
read to it, only give to it). A delegation reserve that accepts resources is better
than one that resources are taken from, since the latter is involuntary. Internally it
is a reserve like any other, but maybe it should not be explicitly enumerated?

Another way to handle it: a reserve has the can view taps in/out capability. Any process
that has the corresponding capability can view taps and the reserves at either end. But
for the remote reserve, we might not have the privilege to view more. Even with this, we'd
still need special delegation support.
*/

