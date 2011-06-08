#ifdef CONFIG_CINDER

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/cinder.h>
#include <linux/sched.h>

#include <linux/string.h>
#include <linux/semaphore.h>
#include <linux/wait.h>
#include <linux/idr.h>
#include <linux/ktime.h>
#include <linux/delay.h>

//TODO: Add get_active_reserve() method

struct cinder_reserve root_reserve;
struct cinder_reserve_process_link init_root_link;
struct cinder_reserve_process_link init_child_link;

spinlock_t cinder_id_lock;
struct idr cinder_reserve_idr;
struct idr cinder_tap_idr;

spinlock_t cinder_global_list_lock;
struct list_head cinder_global_reserve_list;

spinlock_t cinder_ready_lock;
int cinder_ready;

long timespec_to_ms(struct timespec *ts)
{
	return (ts->tv_sec * 1000) + (ts->tv_nsec / 1000000);
}

int cinder_tap_daemon(void * unused)
{
	struct cinder_reserve *src_reserve, *dest_reserve;
	struct cinder_tap *tap;
	struct timespec ts, prev_ts;
	long time_delta_ms, err, current_ms;

	ktime_get_ts(&prev_ts);

	for (;;) {
		ktime_get_ts(&ts);
		current_ms = timespec_to_ms(&ts);
		time_delta_ms = current_ms - timespec_to_ms(&prev_ts);
		err = cinder_battery_root_sync();
		if (err) {
			printk("INFO CINDER: Unable to sync root reserve with battery!");
		}

		// TODO: How often should root reserve and battery be synced

		/* While we hold this lock, reserves cannot be deleted */
		spin_lock(&cinder_global_list_lock);

		/* For each reserve */
		list_for_each_entry(src_reserve,
				    &cinder_global_reserve_list, 
				    global_list) {
			long total_debit_desired = 0;
			long total_available;

			/* While we have reserve lock, taps cannot be deleted */
			spin_lock(&src_reserve->reserve_lock);
			total_available = src_reserve->capacity;

			/* If reserve is empty, continue */
			if (total_available <= 0) {
				spin_unlock(&src_reserve->reserve_lock);
				continue;
			}

			/* First figure out how much we want to debit and add it
			 * to the total_debit accumulator for each tap */
			list_for_each_entry(tap,
					    &src_reserve->taps_from,
					    reserve_from) {

				long tap_delta = current_ms - tap->time_of_last_flow;
				long type, rate;

				spin_lock(&tap->tap_lock);

				type = tap->type;
				rate = tap->rate;

				// TODO: Sort out numerical edge cases
				// Accumulator?

				if (tap->type == CINDER_TAP_RATE_CONSTANT) {
					// TODO: Finalize constant tap rate as being per second
					tap->draw_amount = (tap->rate * tap_delta) / CINDER_TAP_DRAW_INTERVAL_MS;
				}
				else if (tap->type == CINDER_TAP_RATE_PROPORTIONAL) {
					// TODO: Finalize proportional tap rate as being per second
					tap->draw_amount = (total_available * tap->rate * tap_delta) / (100 * CINDER_TAP_DRAW_INTERVAL_MS);
				}
				else {
					spin_unlock(&tap->tap_lock);
					panic("Cinder: Invalid tap type!");
				}
				spin_unlock(&tap->tap_lock);

				if (tap->draw_amount > 0 || tap->rate == 0) {
					/* If draw_amount > 0, or rate is 0, 
					 * then tap 'flowed' */
					tap->time_of_last_flow = current_ms;
				}

				total_debit_desired += tap->draw_amount;
			}

			/* Now go through each tap again and debit from the 
			 * source reserve. We aren't committing the resources
			 * to the destination reserve yet though... */

			if (total_debit_desired > 0) {
				list_for_each_entry(tap,
						    &src_reserve->taps_from,
						    reserve_from) {
					long debit_amount;

					/* Calculate actual debit amount and debit from source*/
					if (total_debit_desired > total_available) {
						debit_amount = (tap->draw_amount * total_available) / total_debit_desired;
					}
					else {
						debit_amount = tap->draw_amount;
					}
					src_reserve->capacity -= debit_amount;
					src_reserve->lifetime_usage += debit_amount;

					/* Add to staging area for dest reserve. Note
		                           no further locking required here since we 
		                           'own' the value_to_add field. */
					tap->dest_reserve->value_to_add += debit_amount;
				}
			}
			spin_unlock(&src_reserve->reserve_lock);
		}

		/* Now add transferred value to each reserve */
		list_for_each_entry(dest_reserve,
				    &cinder_global_reserve_list, 
				    global_list) {
			long prev_capacity;

			spin_lock(&dest_reserve->reserve_lock);
			prev_capacity = dest_reserve->capacity;
			dest_reserve->capacity += dest_reserve->value_to_add;
			dest_reserve->lifetime_input += dest_reserve->value_to_add;
			dest_reserve->value_to_add = 0;
			spin_unlock(&dest_reserve->reserve_lock);
		}
		
		spin_unlock(&cinder_global_list_lock);
		prev_ts = ts;
		msleep(CINDER_TAP_THREAD_SLEEPTIME);
	}
	return 0;
}

/**
 * cinder_generate_id : Generate ID for cinder object
 * @idr : The idr object used
 *
 * Called with no locks held.
 */

int cinder_generate_id(struct idr *idp, void *p, int *id)
{
	int ret;
again:
	if (idr_pre_get(idp, GFP_KERNEL) == 0)
		return -ENOMEM;
	spin_lock(&cinder_id_lock);
	ret = idr_get_new(idp, p, id);
	if (ret == -EAGAIN) {
		spin_unlock(&cinder_id_lock);
		goto again;
	}

	spin_unlock(&cinder_id_lock);
	return ret;
}


void cinder_put_id(struct idr *idp, int id)
{
	spin_lock(&cinder_id_lock);
	idr_remove(idp, id);
	spin_unlock(&cinder_id_lock);
}

/**
 * cinder_setup - boot time Cinder setup
 * @swapper_task : task with pid 0
 *
 * Called at boot time by the swapper thread. Sets up the root reserve and
 * initial link between the swapper task and the root reserve. However, it does
 * NOT set the root reserve with the battery data - that task is left to init.
 */
void cinder_setup(struct task_struct *swapper_task)
{
	int err;

	/* For IDs */
	cinder_id_lock = __SPIN_LOCK_UNLOCKED(cinder_id_lock);
	idr_init(&cinder_reserve_idr);
	idr_init(&cinder_tap_idr);

	/* Global tap list */
	cinder_global_list_lock = __SPIN_LOCK_UNLOCKED(cinder_global_list_lock);
	INIT_LIST_HEAD(&cinder_global_reserve_list);

	cinder_ready_lock = __SPIN_LOCK_UNLOCKED(cinder_ready_lock);
	cinder_ready = 0;

	/* No locks needed here, swapper is the only thing running */
	err = cinder_setup_reserve(&root_reserve, "root_reserve");

	if (err != 0)
		panic("Boot could not set up root reserve: %d", err);

	cinder_setup_task_common(swapper_task);
	cinder_setup_reserve_link(&init_root_link,
				  &init_child_link, 
				  swapper_task, 
				  &root_reserve, 
				  CINDER_CAP_ALL);
	swapper_task->active_reserve = &root_reserve;
}

/**
 * cinder_setup_reserve - initial reserve setup
 * @reserve : the reserve we are setting up
 * @name : the name of the reserve
 *
 * Perform initial setup of a just allocated reserve. The reserve is empty, has
 * no processes linked to it, has no taps, and has the given name. No locks are
 * needed since only current can access the reserve.
 */
int cinder_setup_reserve(struct cinder_reserve *reserve, const char *name)
{
	int err, id;

	err = cinder_generate_id(&cinder_reserve_idr, reserve, &id);
	if (err)
		return err;

	reserve->id = id;	
	reserve->capacity = 0;
	reserve->lifetime_input = 0;
	reserve->lifetime_usage = 0;
	reserve->value_to_add = 0; /* For taps thread */

	INIT_LIST_HEAD(&reserve->taps_to);
	INIT_LIST_HEAD(&reserve->taps_from);
	INIT_LIST_HEAD(&reserve->process_links);

	atomic_set(&reserve->refcount, 0);
	reserve->reserve_lock = __SPIN_LOCK_UNLOCKED(reserve->reserve_lock);
	strncpy(reserve->name, name, CINDER_MAX_NAMELEN);
	reserve->name[CINDER_MAX_NAMELEN - 1] = 0;

	/* Add to global reserve list (for tap adjustments) */
	spin_lock(&cinder_global_list_lock);
	list_add_tail(&reserve->global_list, &cinder_global_reserve_list);
	spin_unlock(&cinder_global_list_lock);

	return 0;
}

/**
 * cinder_cleanup_reserve - frees reserve
 * @reserve : the reserve we are disposing off
 *
 * Called when refcount for reserve is 0. At this point, there are no
 * processes that still have a link with the reserve. In addition, there
 * are no taps either leading to or from this reserve. If not root reserve,
 * add energy in reserve back to root. Freeing root reserve is a bug.
 * Finally, free reserve memory and return.
 */
void cinder_cleanup_reserve(struct cinder_reserve *reserve)
{
	long spare_capacity;
	if (reserve == &root_reserve)
		panic("CINDER BUG: Tried to free root reserve.\n");

	spare_capacity = (reserve->capacity > 0 ? reserve->capacity : 0);
	if (spare_capacity) {
		spin_lock(&root_reserve.reserve_lock);
		root_reserve.capacity += spare_capacity;
		root_reserve.lifetime_input += spare_capacity;
		spin_unlock(&root_reserve.reserve_lock);
	}

	/* Remove from global reserve list */
	spin_lock(&cinder_global_list_lock);
	list_del(&reserve->global_list);
	spin_unlock(&cinder_global_list_lock);

	cinder_put_id(&cinder_reserve_idr, reserve->id);
	kfree(reserve);
}

/**
 * cinder_setup_task_common - initializes cinder structures for new task
 * @tsk : the task we are initializing
 *
 * Called to setup Cinder structures on a new task. Initially, the task has
 * access to no reserves, and is not within a kthread_fork call. This task may
 * either be a new kernel thread, a new thread, or a new process. This method
 * does NOT set the active reserve for the task.
 */
void cinder_setup_task_common(struct task_struct *tsk)
{
	tsk->time_sched_start = 0;

	init_MUTEX(&tsk->cinder_lock);
	tsk->kthread_fork = 0;
	tsk->num_reserves = 0;
	tsk->num_child_reserves = 0;
	tsk->num_taps = 0;

	INIT_LIST_HEAD(&tsk->reserves);
	INIT_LIST_HEAD(&tsk->child_create_reserves);
	INIT_LIST_HEAD(&tsk->taps);

	tsk->network_acct_lock = __SPIN_LOCK_UNLOCKED(tsk->network_acct_lock);
	INIT_LIST_HEAD(&tsk->network_power_acct);

	tsk->resource_accumulator = 0;
	tsk->resources_used = 0;

	tsk->should_debit = 1;
	tsk->runb = 1;
	tsk->runb_lock = __SPIN_LOCK_UNLOCKED(tsk->runb_lock);
	init_waitqueue_head(&tsk->testwq);
	init_waitqueue_entry(&tsk->cwq, tsk);
}

/**
 * cinder_cleanup_task - cleans up cinder structures for exiting task
 * @tsk : the task we are cleaning up
 *
 * Called to cleanup Cinder structures on an exiting task. If task is kthread
 * or is is thread group leader, we clean up all process<->reserve links for the
 * task, possibly deleting some reserves as well. If just regular thread, no-op.
 */
void cinder_cleanup_task(struct task_struct *tsk)
{
	cinder_cleanup_child_reserve_links(tsk, tsk->group_leader);

	if (thread_group_leader(tsk) || tsk->flags & PF_KTHREAD) {
		cinder_cleanup_reserve_links(tsk);
	}

	cinder_cleanup_tsk_netdev_acct(tsk);
}

/**
 * cinder_setup_reserve_link - setup newly allocated process<->reserve link
 * @link : the link we are setting up
 * @tsk : the task that we are setting the link up for
 * @reserve : the reserve we are linking to
 * @capabilities : the privileges the task has on the reserve
 * @child_access : true if forked children get access to this reserve
 *
 * Called to setup a link between a task and a process with given capabilities.
 * Requirements :
 * 1. Caller must ensure that the provided task struct is either a kthread or a
 * thread group leader. 
 * 2. Caller should make sure he has task's cinder_lock mutex if necessary.
 */
void cinder_setup_reserve_link(struct cinder_reserve_process_link *link,
			       struct cinder_reserve_process_link *child_link,
			       struct task_struct *tsk,
			       struct cinder_reserve *reserve,
			       unsigned int capabilities)
{
	cinder_connect_link_to_reserve(link, reserve, capabilities);
	cinder_connect_link_to_process(link, tsk);
	if (child_link) {
		cinder_add_reserve_to_child_list(link, child_link, tsk, tsk, capabilities);
	}
}

/**
 * cinder_connect_link_to_reserve - connect new process<->reserve link to reserve
 * @link : the link we are setting up
 * @reserve : the reserve we are linking to
 * @capabilities : the privileges the task has on the reserve
 *
 * Called to connect a reserve to a newly allocated process<->reserve link. Must
 * ensure that current process' cinder_lock is held so reserve does not vanish.
 */
void cinder_connect_link_to_reserve(struct cinder_reserve_process_link *link,
				    struct cinder_reserve *reserve,
				    unsigned int capabilities)
{
	link->capabilities = capabilities;
	link->reserve = reserve;

	/* New process accessing reserve : bump refcount */
	atomic_inc(&reserve->refcount);

	/* Add to reserve's list */
	spin_lock(&reserve->reserve_lock);
	list_add_tail(&link->reserve_list, &reserve->process_links);
	spin_unlock(&reserve->reserve_lock);
}

/**
 * cinder_connect_link_to_process - connect new process<->reserve link to task
 * @link : the link we are setting up
 * @tsk : the task that we are setting the link up for
 * @child_access : true if forked children get access to this reserve
 *
 * Called to connect new link that is already connected to reserve, to a task.
 * 1. Caller must ensure that the provided task struct is either a kthread or a
 * thread group leader. 
 * 2. Caller must ensure he has the task's cinder_lock.
 */
void cinder_connect_link_to_process(struct cinder_reserve_process_link *link,
				    struct task_struct *tsk)
{
	link->process = tsk;
	link->thread = tsk;
	list_add(&link->process_list, &tsk->reserves);
	tsk->num_reserves++;
}

/**
 * cinder_add_reserve_to_child_list - Add reserve to child list for thread
 * @link : the link between the process and reserve
 * @clink : the link for the thread's child list
 * @tsk : the thread that we are setting the link up for
 * @group_leader : The thread group leader
 * @capabilities : The capabilities forked children will receive.
 *
 * Called to connect reserve to thread's list of child reserves.
 * 1. Caller must ensure that the reserve<->process link is already set up.
 * 2. Caller must ensure he has the task's cinder_lock.
 */
void cinder_add_reserve_to_child_list(struct cinder_reserve_process_link *link,
				      struct cinder_reserve_process_link *clink,
				      struct task_struct *tsk,
				      struct task_struct *group_leader, 
				      unsigned int capabilities)
{
	clink->process = group_leader;
	clink->thread = tsk;
	clink->capabilities = capabilities;
	clink->reserve = link->reserve;

	list_add_tail(&clink->process_list, &tsk->child_create_reserves);
	tsk->num_child_reserves++;
}

/**
 * cinder_remove_reserve_from_child_list - Remove reserve from child list for thread
 * @clink : the link we are removing
 *
 * Removes link from thread's child list. Caller has cinder_lock for process.
 */
void cinder_remove_reserve_from_child_list(struct cinder_reserve_process_link *clink)
{
	list_del(&clink->process_list);
	clink->thread->num_child_reserves--;
	kfree(clink);
}

/**
 * cinder_cleanup_reserve_link - cleanup process<->reserve link
 * @link : the link we are setting up
 *
 * Called to cleanup a link between a task and a process. Any existing taps
 * involving the reserve created by the current process are deleted. The reserve
 * refcount is decremented; if it goes to 0, the reserve is cleaned up.
 *
 * Called with process' cinder_lock held.
 */
void cinder_cleanup_reserve_link(struct cinder_reserve_process_link *link)
{
	cinder_remove_reserve_taps(link);
	cinder_detach_link_from_reserve(link);
	cinder_detach_link_from_process(link);
	kfree(link);
}

/**
 * cinder_remove_reserve_taps - remove taps involving reserve from process
 * @link : the link we are detaching
 *
 * Removes taps either to or from given reserve that were created by the
 * current process.
 *
 * Called with process' cinder_lock held.
 */
void cinder_remove_reserve_taps(struct cinder_reserve_process_link *link)
{
	struct cinder_tap *current_tap, *tmp;
	struct task_struct *group_leader = link->process;

	list_for_each_entry_safe(current_tap, tmp, &group_leader->taps, process_list) {
		if (current_tap->src_reserve != link->reserve &&
		    current_tap->dest_reserve != link->reserve)
			continue;
		cinder_remove_tap(current_tap);
	}
}

/**
 * cinder_remove_tap - remove the given tap from it's process and delete
 * @tap : the tap we are removing
 *
 * Called with process' cinder lock held.
 */
void cinder_remove_tap(struct cinder_tap *tap)
{
	/* Remove from reserve's list of taps */
	spin_lock(&tap->src_reserve);
	list_del(&tap->reserve_from);
	spin_unlock(&tap->src_reserve);

	spin_lock(&tap->dest_reserve);
	list_del(&tap->reserve_to);
	spin_unlock(&tap->dest_reserve);

	/* Remove tap from process' list of taps. */
	list_del(&tap->process_list);
	tap->creator->num_taps--;

	cinder_put_id(&cinder_tap_idr, tap->id);
	kfree(tap);
}

/**
 * cinder_detach_link_from_process - remove link from process
 * @link : the link we are detaching
 *
 * Called to detach a link from a process. Any existing taps involving the
 * given process and reserve have already been deleted. The link has already
 * been detached from the reserve, which may have been deleted if it was the
 * last link to the reserve.
 *
 * Called with process' cinder_lock held.
 */
void cinder_detach_link_from_process(struct cinder_reserve_process_link *link)
{
	list_del(&link->process_list);
	link->process->num_reserves--;
}

/**
 * cinder_detach_link_from_reserve - remove link from reserve
 * @link : the link we are detaching
 *
 * Called to detach a link from a reserve. Any existing taps involving the
 * given process and reserve have already been deleted. The reserve
 * refcount is decremented; if it goes to 0, the reserve is cleaned up.
 *
 * Called with process' cinder_lock held.
 */
void cinder_detach_link_from_reserve(struct cinder_reserve_process_link *link)
{
	struct cinder_reserve *reserve = link->reserve;

	spin_lock(&reserve->reserve_lock);
	list_del(&link->reserve_list);
	spin_unlock(&reserve->reserve_lock);

	if (atomic_dec_and_test(&link->reserve->refcount))
		cinder_cleanup_reserve(link->reserve);
}

/**
 * cinder_cleanup_reserve_links - cleanup all process<->reserve links for process
 * @tsk : the process we are cleaning up the links for
 *
 * Called either on process exit or on error during process creation. Caller
 * must ensure tsk is a kthread or thread group leader.
 */
void cinder_cleanup_reserve_links(struct task_struct *group_leader)
{
	struct cinder_reserve_process_link *reserve_link, *tmp_link;

	down(&group_leader->cinder_lock);

	/* For each reserve process can access, do cleanup */
	list_for_each_entry_safe(reserve_link, 
				 tmp_link, 
				 &group_leader->reserves, 
				 process_list) {
		cinder_cleanup_reserve_link(reserve_link);
	}
	up(&group_leader->cinder_lock);
}

/**
 * cinder_cleanup_child_reserve_links - cleanup all child reserve list entries 
   for thread
 * @tsk : the thread we are cleaning up the entries for
 * @group_leader : the thread group leader for tsk
 *
 * Called either on thread exit or on error during process creation. Caller must
 * ensure that either the process' cinder_lock is held, or that it is not
 * necessary.
 */
void cinder_cleanup_child_reserve_links(struct task_struct *tsk, 
					struct task_struct *group_leader)
{
	struct cinder_reserve_process_link *reserve_link, *tmp_link;
	
	down(&group_leader->cinder_lock);

	list_for_each_entry_safe(reserve_link,
				 tmp_link, 
				 &tsk->child_create_reserves,
				 process_list) {
		cinder_remove_reserve_from_child_list(reserve_link);
	}
	up(&group_leader->cinder_lock);
}

/**
 * cinder_battery_root_sync - Set root reserve energy based on battery value
 *
 * Called by init thread during system boot before running user init program.
 */
long cinder_battery_root_sync()
{
	long battery_life = cinder_current_battery_level();
	long battery_capacity = cinder_max_battery_level();
	if (battery_life < 0) {
		return battery_life;
	}
	spin_lock(&root_reserve.reserve_lock);
	root_reserve.capacity = (battery_life * battery_capacity) / 100;
	spin_unlock(&root_reserve.reserve_lock);
	return 0;
}

/**
 * cinder_setup_kthread_reserve - Setup link between root_reserve and kthread
 * @tsk : the kthread we are setting up
 *
 * Called by copy_process() during fork if forking a kthread.
 */
int cinder_setup_kthread_reserve(struct task_struct *tsk)
{
	struct cinder_reserve_process_link *link, *child_link;

	link = kmalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
		return -ENOMEM;

	child_link = kmalloc(sizeof(*child_link), GFP_KERNEL);
	if (!child_link) {
		kfree(link);
		return -ENOMEM;
	}

	/* Since we are forking a new process, don't need lock here */
	cinder_setup_reserve_link(link, child_link, tsk, &root_reserve, CINDER_CAP_ALL);
	tsk->active_reserve = &root_reserve;
	return 0;
}

/**
 * cinder_setup_child_reserves - Setup links between reserves and newly forked process
 * @child : the newly forked process
 * @parent : the parent process
 *
 * Called by copy_process() during fork if forking a new process (ie. not a 
 * thread or kthread).
 */
int cinder_setup_child_reserves(struct task_struct *child, struct task_struct *parent)
{
	struct cinder_reserve_process_link *reserve_link, *child_list_link;
	struct cinder_reserve_process_link *parent_link;
	struct task_struct *group_lead;
	int found_active = 0;

	group_lead = parent->group_leader;

	down(&group_lead->cinder_lock);

	/* Check how many child reserves we have. If none, fail. */
	if (parent->num_child_reserves < 1) {
		up(&group_lead->cinder_lock);
		return -EINVAL;
	}

	/* For ever reserve in the child reserve list, */
	list_for_each_entry(parent_link,
			    &parent->child_create_reserves, 
			    process_list) {
		struct cinder_reserve *reserve = parent_link->reserve;
		unsigned int capabilities = parent_link->capabilities;

		/* Allocate memory (we can sleep with a semaphore) */
		reserve_link = kmalloc(sizeof(*reserve_link), GFP_KERNEL);
		if (!reserve_link) {
			up(&group_lead->cinder_lock);
			goto bad_alloc;
		}
		child_list_link = kmalloc(sizeof(*child_list_link), GFP_KERNEL);
		if (!child_list_link) {
			up(&group_lead->cinder_lock);
			kfree(reserve_link);
			goto bad_alloc;
		}

		/* Since we are forking a new process, no other locks needed here */
		cinder_setup_reserve_link(reserve_link, child_list_link, child, reserve, capabilities);
		if (!found_active) {
			if (capabilities & CINDER_CAP_RESERVE_DRAW) {
				found_active = 1;
				child->active_reserve = reserve;
			}
		}
	}

	up(&group_lead->cinder_lock);
	return 0;

bad_alloc:
	cinder_cleanup_child_reserve_links(child, child);
	cinder_cleanup_reserve_links(child);
	return -ENOMEM;
}

/**
 * cinder_setup_forked_thread - Setup links between reserves and newly forked thread
 * @thread : the newly forked thread
 * @parent : the parent process
 *
 * Called by copy_process() during fork if forking a new thread (ie. not a new 
 * process or kthread).
 */
int cinder_setup_forked_thread(struct task_struct *thread, struct task_struct *parent)
{
	struct cinder_reserve_process_link *parent_link, *child_list_link;
	struct task_struct *group_lead;

	group_lead = parent->group_leader;
	down(&group_lead->cinder_lock);

	/* For ever reserve in the child reserve list of the parent thread, */
	list_for_each_entry(parent_link,
			    &parent->child_create_reserves, 
			    process_list) {

		unsigned int capabilities = parent_link->capabilities;

		child_list_link = kmalloc(sizeof(*child_list_link), GFP_KERNEL);
		if (!child_list_link) {
			up(&group_lead->cinder_lock);
			goto bad_alloc;
		}

		/* Copy over links from parent thread's child reserve list */
		cinder_add_reserve_to_child_list(parent_link, 
						 child_list_link,
						 thread, 
						 group_lead,
						 capabilities);
	}

	thread->active_reserve = parent->active_reserve;
	up(&group_lead->cinder_lock);	
	return 0;

bad_alloc:
	cinder_cleanup_child_reserve_links(thread, group_lead);
	return -ENOMEM;
}

/**
 * cinder_create_reserve - Create reserve on behalf of process
 * @name : the name for the reserve
 * @len : number of bytes in name, including null terminator
 *
 * Creates new empty reserve with no taps that process has full capabilities on.
 */
int cinder_create_reserve(const char *name, unsigned int len)
{
	int err;
	struct cinder_reserve *reserve = NULL;
	struct cinder_reserve_process_link *link = NULL;
	struct task_struct *group_leader;

	/* Allocate reserve and link */
	reserve = kmalloc(sizeof(*reserve), GFP_KERNEL);
	if (!reserve)
		return -ENOMEM;
	
	link = kmalloc(sizeof(*link), GFP_KERNEL);
	if (!link)
		goto out_free;

	/* Setup structures inside thread group leader and return */
	group_leader = current->group_leader;

	/* Setup reserve : no locks needed here since it's a new one */
	err = cinder_setup_reserve(reserve, name);
	if (err) {
		kfree(reserve);
		kfree(link);
		return err;
	}

	/* Setup link : need reserves lock on thread group leader */
	down(&group_leader->cinder_lock);
	cinder_setup_reserve_link(link, NULL, group_leader, reserve, CINDER_CAP_ALL);
	up(&group_leader->cinder_lock);

	return reserve->id;

out_free:
	kfree(reserve);
	return -ENOMEM;
}

/**
 * sys_create_reserve - Create reserve on behalf of process
 * @name : the name for the reserve
 * @len : number of bytes in name, including null terminator
 *
 * Creates new empty reserve with no taps that process has full capabilities on.
 */
asmlinkage int sys_create_reserve(char __user *name, unsigned int len)
{
	char rname[CINDER_MAX_NAMELEN];
	unsigned int copylen;
	int ret;

	/* Check parameters */
	if (!name || len < 1)
		return -EINVAL;
	copylen = (len < CINDER_MAX_NAMELEN ? len : CINDER_MAX_NAMELEN);

	ret = copy_from_user(rname, name, copylen);
	if (ret)
		return -EFAULT;
	rname[copylen - 1] = 0;

	return cinder_create_reserve(rname, copylen);
}

/**
 * sys_put_reserve - Drop process' reference to reserve (possibly deleting reserve).
 * @reserve_id : the id for the reserve
 *
 * Drops process' reference to this reserve. Deletes all taps either to or from
 * reserve that were created by the process. Removes link between process and
 * reserve, cleaning up reserve if this was the last process that could access
 * it.
 */
asmlinkage long sys_put_reserve(int reserve_id)
{
	struct task_struct *group_leader, *t;
	struct cinder_reserve_process_link *link = NULL, *current_link;
	struct cinder_reserve *reserve;
	int reserve_in_use = 0;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			link = current_link;
			break;
		}
	}
	/* If link is NULL, then we didn't have access to the reserve anyways */
	if (!link) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	reserve = link->reserve;
	
	/* For each thread in group, check if this is the active reserve. 
	 * If so, we cannot perform this operation. */
	t = group_leader;	
	do {
		if (t->active_reserve == reserve) {
			/* Ruh roh, trying to put reserve that is active */
			reserve_in_use = 1;
			goto done_active_check;
		}
		t = next_thread(t);
	}
	while (t != group_leader);

done_active_check:
	if (reserve_in_use) {
		up(&group_leader->cinder_lock);
		return -EBUSY;
	}

	/* Alright, we can kill this reserve. We are severing all ties
	 * to it, which means we must:
	 * 0. Remove reserve from child_reserve lists for each thread.
	 * 1. Remove all taps to/from reserve that this process created
	 * 2. Remove link from the process' list of links
	 * 3. If present, remove link from process' list of child reserve links
	 * 4. Remove link from the reserve's list of links
	 * 5. Decrement refcount on reserve (needs lock on reserve)
	 * 6. If refcount is zero, clean up reserve as well.
	 */
	cinder_remove_reserve_from_child_lists(reserve_id, group_leader);
	cinder_cleanup_reserve_link(link);

	up(&group_leader->cinder_lock);
	return 0;
}

/**
 * cinder_remove_reserve_from_child_lists - Remove given reserve from child lists
 * for each thread in process.
 * @reserve_id : the id for the reserve
 * @group_leader : the group leader for this thread group
 */
void cinder_remove_reserve_from_child_lists(long reserve_id,
					    struct task_struct *group_leader)
{
	struct task_struct *t = group_leader;

	do {
		cinder_remove_reserve_from_child_list_by_id(reserve_id, t);
		t = next_thread(t);
	}
	while (t != group_leader);	
}

/**
 * cinder_remove_reserve_from_child_list - Remove given reserve from child lists
 * for given thread.
 * @reserve_id : the id for the reserve
 * @tsk : the thread we are removing from
 */
int cinder_remove_reserve_from_child_list_by_id(long reserve_id, 
					   struct task_struct *tsk)
{
	int removed = 0;
	struct cinder_reserve_process_link *link, *tmp_link;

	list_for_each_entry_safe(link,
				 tmp_link, 
				 &tsk->child_create_reserves,
				 process_list) {
		if(link->reserve->id == reserve_id) {
			cinder_remove_reserve_from_child_list(link);
			removed = 1;
		}
	}
	if (removed)
		return 0;
	else
		return -EINVAL;
}

/**
 * sys_expose_reserve - Expose reserve to target process
 * @pid : the pid for the process that we are granting reserve access to
 * @reserve_id : the id of the reserve
 * @capabilities : the capabilities we are granting to the process
 *
 * Grants access of given reserve to the target process, with the given 
 * capabilities.
 */
asmlinkage long sys_expose_reserve(pid_t pid, int reserve_id, unsigned int capabilities)
{
	int target_has_reserve = 0;
	struct task_struct *group_leader, *target;
	struct cinder_reserve_process_link *link = NULL, *current_link, *new_link;
	struct cinder_reserve *reserve;
	pid_t my_pid;

	/* Can't grant reserve to myself */
	my_pid = task_pid_vnr(current);
	if (my_pid == pid)
		return -EINVAL;

	/* Look for other process */
	rcu_read_lock();
	target = find_task_by_vpid(pid);
	if (!target) {
		rcu_read_unlock();
		return -ESRCH;
	}
	/* Take reference on process' group lead */
	target = target->group_leader;
	get_task_struct(target);
	rcu_read_unlock();

	/* Get our cinder_lock */
	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			link = current_link;
			break;
		}
	}
	/* If link is NULL, then we didn't have access to the reserve anyways */
	if (!link) {
		up(&group_leader->cinder_lock);
		put_task_struct(target);
		return -EINVAL;
	}

	/* Adjust capabilities */
	reserve = link->reserve;
	capabilities &= link->capabilities;

	/* Allocate new link */
	new_link = kmalloc(sizeof(*new_link), GFP_KERNEL);
	if (!new_link) {
		up(&group_leader->cinder_lock);
		put_task_struct(target);
		return -ENOMEM;
	}

	/* Connect link to reserve and release this process' cinder_lock */
	cinder_connect_link_to_reserve(new_link, reserve, capabilities);
	up(&group_leader->cinder_lock);

	/* Add link to target task if necessary */
	down(&target->cinder_lock);

	/* First check if target already has access: */
	list_for_each_entry(current_link, &target->reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			target_has_reserve = 1;
			link = current_link;
			break;
		}
	}
	if (target_has_reserve) {
		/* Target already had access to reserve, so cleanup the new reserve */
		cinder_detach_link_from_reserve(new_link);
		kfree(new_link);

		/* Adjust the capabilities of the link we found to be the sum of
                 * the existing capabilities and the ones we just granted. */
		link->capabilities |= capabilities;
	}
	else {
		/* Target does not have access to reserve, so give it access */
		cinder_connect_link_to_process(new_link, target);
	}
	up(&target->cinder_lock);

	/* Release our reference on target task */
	put_task_struct(target);
	return 0;
}

asmlinkage long sys_reserve_info(int reserve_id, struct reserve_info __user *info)
{
	/* TODO: Add facility for returning tap IDs given user pointer */
	struct task_struct *group_leader;
	struct cinder_reserve_process_link *link = NULL, *current_link;
	struct cinder_reserve *reserve;
	struct reserve_info kinfo;
	int ret;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			link = current_link;
			break;
		}
	}
	/* If link is NULL, then we didn't have access to the reserve anyways */
	if (!link) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	reserve = link->reserve;

	/* Get reserve data */
	kinfo.num_users = atomic_read(&reserve->refcount);
	kinfo.id = reserve->id;
	kinfo.num_process_taps = 0;
	memcpy(kinfo.name, reserve->name, sizeof(reserve->name));

	/* Need lock for reserve capacity and number of taps */	
	spin_lock(&reserve->reserve_lock);
	kinfo.capacity = reserve->capacity;
	kinfo.lifetime_usage = reserve->lifetime_usage;
	kinfo.lifetime_input = reserve->lifetime_input;

	/* TODO: Iterate through taps and return number of taps */
	spin_unlock(&reserve->reserve_lock);

	up(&group_leader->cinder_lock);

	/* Copy to user and return */
	ret = copy_to_user(info, &kinfo, sizeof(kinfo));
	if (ret)
		return -EFAULT;
	return 0;
}

asmlinkage long sys_reserve_transfer(int src_reserve_id, 
                                     int dest_reserve_id, 
                                     long amount, 
                                     long fail_if_insufficient)
{
	struct task_struct *group_leader;
	struct cinder_reserve_process_link *src_link = NULL, *dest_link = NULL; 
	struct cinder_reserve_process_link *current_link = NULL;
	struct cinder_reserve *src_reserve = NULL, *dest_reserve = NULL;
	long transfer_amount;
	int found_src = 0, found_dest = 0;

	/* Check inputs. Allow transferring only positive non-zero amounts
	 * between different reserves. */
	if (amount < 1 || src_reserve_id == dest_reserve_id)
		return -EINVAL;

	group_leader = current->group_leader;

	/* Find both reserves, starting with the source */	
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == src_reserve_id) {
			found_src = 1;
			src_reserve = current_link->reserve;
			src_link = current_link;
			if (found_dest)
				break;
		}
		if (current_link->reserve->id == dest_reserve_id) {
			found_dest = 1;
			dest_reserve = current_link->reserve;
			dest_link = current_link;
			if (found_src)
				break;
		}
	}

	/* Couldn't find */
	if (!found_src || !found_dest) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Check our permissions on each reserve */
	if (!(src_link->capabilities & CINDER_CAP_RESERVE_MODIFY)) {
		up(&group_leader->cinder_lock);
		return -EPERM;
	}

	if (!(dest_link->capabilities & CINDER_CAP_RESERVE_MODIFY)) {
		up(&group_leader->cinder_lock);
		return -EPERM;
	}

	/* Ready to test transfer. */
	spin_lock(&src_reserve->reserve_lock);

	/* If source is empty, automatic fail. */	
	if (src_reserve->capacity < 1) {
		spin_unlock(&src_reserve->reserve_lock);
		up(&group_leader->cinder_lock);
		return -EBUSY;
	}

	/* If we do not have enough and are signalled to do so, fail. */
	if (src_reserve->capacity < amount && fail_if_insufficient) {
		spin_unlock(&src_reserve->reserve_lock);
		up(&group_leader->cinder_lock);
		return -EBUSY;
	}

	/* Determine how much we are transferring and debit that amount */
	transfer_amount = (amount < src_reserve->capacity ? amount : src_reserve->capacity);
	src_reserve->capacity -= transfer_amount;

	/* Update lifetime input value for source reserve */
	src_reserve->lifetime_usage += transfer_amount;

	spin_unlock(&src_reserve->reserve_lock);

	/* Add amount to the destination reserve and return */
	spin_lock(&dest_reserve->reserve_lock);
	dest_reserve->capacity += transfer_amount;

	/* Update lifetime input value */
	dest_reserve->lifetime_input += transfer_amount;

	spin_unlock(&dest_reserve->reserve_lock);

	/* We return how much was transferred */
	up(&group_leader->cinder_lock);
	return transfer_amount;
}

asmlinkage long sys_reserve_level(int reserve_id, long __user *capacity)
{
	struct task_struct *group_leader;
	struct cinder_reserve_process_link *link = NULL, *current_link;
	struct cinder_reserve *reserve;
	long kcapacity;
	int ret;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			link = current_link;
			break;
		}
	}
	/* If link is NULL, then we didn't have access to the reserve anyways */
	if (!link) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	reserve = link->reserve;

	spin_lock(&reserve->reserve_lock);
	kcapacity = reserve->capacity;
	spin_unlock(&reserve->reserve_lock);

	up(&group_leader->cinder_lock);

	ret = copy_to_user(capacity, &kcapacity, sizeof(kcapacity));
	if (ret)
		return -EFAULT;
	return 0;
}

asmlinkage long sys_set_active_reserve(int reserve_id)
{
	struct task_struct *group_leader;
	struct cinder_reserve_process_link *link = NULL, *current_link;
	struct cinder_reserve *reserve;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			link = current_link;
			break;
		}
	}
	/* If link is NULL, then we didn't have access to the reserve anyways */
	if (!link) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	reserve = link->reserve;
	if (!(link->capabilities & CINDER_CAP_RESERVE_DRAW)) {
		up(&group_leader->cinder_lock);
		return -EPERM;
	}

	current->active_reserve = reserve;
	up(&group_leader->cinder_lock);
	return 0;
}

asmlinkage long sys_num_reserves(void)
{
	struct task_struct *group_leader;
	int num_reserves = 0;

	group_leader = current->group_leader;

	down(&group_leader->cinder_lock);
	num_reserves = group_leader->num_reserves;
	up(&group_leader->cinder_lock);

	return num_reserves;
}

asmlinkage int sys_get_reserve(long index)
{
	struct task_struct *group_leader;
	struct cinder_reserve_process_link *link = NULL, *current_link;
	long reserve_id;
	int curr = 0;

	if (index < 0)
		return -EINVAL;

	group_leader = current->group_leader;

	down(&group_leader->cinder_lock);
	
	/* Check if index is out of range */
	if (index >= group_leader->num_reserves) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Iterate till we're at the right place. */
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (index == curr) {
			link = current_link;
			break;
		}
		curr++;
	}

	/* Return the id */
	BUG_ON(!link);
	reserve_id = link->reserve->id;	
	up(&group_leader->cinder_lock);

	return reserve_id;
}

asmlinkage long sys_self_bill(long billing_type, long amount)
{
	struct task_struct *group_leader;

	if (amount < 1)
		return -EINVAL;

	group_leader = current->group_leader;

	down(&group_leader->cinder_lock);
	spin_lock(&current->active_reserve->reserve_lock);

	current->active_reserve->capacity -= amount;

	/* Update lifetime usage counter */
	current->active_reserve->lifetime_usage += amount;

	spin_unlock(&current->active_reserve->reserve_lock);
	up(&group_leader->cinder_lock);

	return 0;
}

int cinder_create_tap(char *name, int len, long src_reserve_id, long dest_reserve_id)
{
	struct task_struct *group_leader;
	struct cinder_reserve_process_link *src_link = NULL, *dest_link = NULL; 
	struct cinder_reserve_process_link *current_link = NULL;
	struct cinder_reserve *src_reserve = NULL, *dest_reserve = NULL;
	struct cinder_tap *tap;
	struct timespec ts;
	int found_src = 0, found_dest = 0, err, id;

	tap = kmalloc(sizeof(*tap), GFP_KERNEL);
	if (!tap)
		return -ENOMEM;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == src_reserve_id) {
			found_src = 1;
			src_reserve = current_link->reserve;
			src_link = current_link;
			if (found_dest)
				break;
		}
		if (current_link->reserve->id == dest_reserve_id) {
			found_dest = 1;
			dest_reserve = current_link->reserve;
			dest_link = current_link;
			if (found_src)
				break;
		}
	}

	/* Couldn't find */
	if (!found_src || !found_dest) {
		up(&group_leader->cinder_lock);
		kfree(tap);
		return -EINVAL;
	}

	/* Check our permissions on each reserve */
	if (!(src_link->capabilities & CINDER_CAP_RESERVE_MODIFY)) {
		up(&group_leader->cinder_lock);
		kfree(tap);
		return -EPERM;
	}

	if (!(dest_link->capabilities & CINDER_CAP_RESERVE_MODIFY)) {
		up(&group_leader->cinder_lock);
		kfree(tap);
		return -EPERM;
	}

	/* Generate id */
	err = cinder_generate_id(&cinder_tap_idr, tap, &id);
	if (err) {
		up(&group_leader->cinder_lock);
		kfree(tap);
		return err;
	}

	/* Set parameters for tap, including defaults for type and rate */
	tap->id = id;
	tap->rate = 0;
	tap->type = CINDER_TAP_RATE_CONSTANT;
	tap->creator = group_leader;
	tap->src_reserve = src_reserve;
	tap->dest_reserve = dest_reserve;

	tap->tap_lock = __SPIN_LOCK_UNLOCKED(tap->tap_lock);
	
	/* Parameters used by tap adjuster kthread */
	ktime_get_ts(&ts);
	tap->time_of_last_flow = timespec_to_ms(&ts);
	tap->draw_amount = 0;

	/* Set name */
	strncpy(tap->name, name, len);
	tap->name[len] = 0;

	/* Add to list of taps for reserves */
	spin_lock(&src_reserve->reserve_lock);
	list_add_tail(&tap->reserve_from, &src_reserve->taps_from);
	spin_unlock(&src_reserve->reserve_lock);

	spin_lock(&dest_reserve->reserve_lock);
	list_add_tail(&tap->reserve_to, &dest_reserve->taps_to);
	spin_unlock(&dest_reserve->reserve_lock);

	/* Add to list of taps for process */
	group_leader->num_taps++;
	list_add_tail(&tap->process_list, &group_leader->taps);

	up(&group_leader->cinder_lock);
	return id;
}

asmlinkage int sys_create_tap(char __user *name, int len, int srcReserve, int destReserve)
{
	char tname[CINDER_MAX_NAMELEN];
	unsigned int copylen;
	int ret;

	/* Check parameters */
	if (!name || len < 1 || srcReserve == destReserve)
		return -EINVAL;

	copylen = (len < CINDER_MAX_NAMELEN ? len : CINDER_MAX_NAMELEN);

	ret = copy_from_user(tname, name, copylen);
	if (ret)
		return -EFAULT;
	tname[copylen - 1] = 0;

	return cinder_create_tap(tname, copylen, srcReserve, destReserve);
}

asmlinkage long sys_delete_tap(int tap_id)
{
	struct task_struct *group_leader;
	struct cinder_tap *tap = NULL, *current_tap;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this tap */	
	list_for_each_entry(current_tap, &group_leader->taps, process_list) {
		if (current_tap->id == tap_id) {
			/* Found it! */
			tap = current_tap;
			break;
		}
	}
	/* Verify the ID */
	if (!tap || tap->creator != group_leader) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Ok, we found tap and we are owner. Perform remove... */
	cinder_remove_tap(tap);

	up(&group_leader->cinder_lock);
	return 0;
}

asmlinkage long sys_tap_info(int tap_id, struct tap_info __user *info)
{
	struct task_struct *group_leader;
	struct cinder_tap *tap = NULL, *current_tap;
	struct tap_info kinfo;
	int ret;

	if (!info)
		return -EINVAL;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this tap */	
	list_for_each_entry(current_tap, &group_leader->taps, process_list) {
		if (current_tap->id == tap_id) {
			/* Found it! */
			tap = current_tap;
			break;
		}
	}
	/* Verify the ID */
	if (!tap || tap->creator != group_leader) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Prepare data for copy */
	spin_lock(&tap->tap_lock);
	kinfo.id = tap->id;
	kinfo.rate = tap->rate;
	kinfo.type = tap->type;

	kinfo.reserve_to = tap->dest_reserve->id;
	kinfo.reserve_from = tap->src_reserve->id;

	memcpy(kinfo.name, tap->name, CINDER_MAX_NAMELEN);
	kinfo.creator = task_pid_vnr(group_leader);
	spin_unlock(&tap->tap_lock);

	up(&group_leader->cinder_lock);

	/* Copy to user and return */
	ret = copy_to_user(info, &kinfo, sizeof(kinfo));
	if (ret)
		return -EFAULT;
	return 0;
}

asmlinkage long sys_tap_set_rate(int tap_id, long rate_type, long value)
{
	struct task_struct *group_leader;
	struct cinder_tap *tap = NULL, *current_tap;

	/* Verify parameters */
	if ((rate_type != CINDER_TAP_RATE_CONSTANT && 
	    rate_type != CINDER_TAP_RATE_PROPORTIONAL) ||
	    value < 0)
		return -EINVAL;

	if (rate_type == CINDER_TAP_RATE_PROPORTIONAL && value > 100)
		return -EINVAL;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this tap */	
	list_for_each_entry(current_tap, &group_leader->taps, process_list) {
		if (current_tap->id == tap_id) {
			/* Found it! */
			tap = current_tap;
			break;
		}
	}
	/* Verify the ID */
	if (!tap || tap->creator != group_leader) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Everything checks out. Set and return. */
	spin_lock(&tap->tap_lock);	
	tap->rate = value;
	tap->type = rate_type;
	spin_unlock(&tap->tap_lock);

	up(&group_leader->cinder_lock);
	return 0;
}

asmlinkage long sys_num_taps(void)
{
	struct task_struct *group_leader;
	int num_taps = 0;

	group_leader = current->group_leader;

	down(&group_leader->cinder_lock);
	num_taps = group_leader->num_taps;
	up(&group_leader->cinder_lock);

	return num_taps;
}

asmlinkage int sys_get_tap(long index)
{
	struct task_struct *group_leader;
	struct cinder_tap *tap = NULL, *current_tap;
	long tap_id;
	int curr = 0;

	if (index < 0)
		return -EINVAL;

	group_leader = current->group_leader;

	down(&group_leader->cinder_lock);
	
	/* Check if index is out of range */
	if (index >= group_leader->num_taps) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Iterate till we're at the right place. */
	list_for_each_entry(current_tap, &group_leader->taps, process_list) {
		if (index == curr) {
			tap = current_tap;
			break;
		}
		curr++;
	}

	/* Return the id */
	BUG_ON(!tap);
	tap_id = tap->id;	
	up(&group_leader->cinder_lock);

	return tap_id;
}

asmlinkage long sys_starve(pid_t pid)
{
	struct task_struct *target;
	int runb;
	pid_t thepid;

	/* Look for other process */
	rcu_read_lock();
	target = find_task_by_vpid(pid);
	if (!target) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/* Take reference */
	get_task_struct(target);
	rcu_read_unlock();

	spin_lock(&target->runb_lock);
	target->runb = 0;
	runb = target->runb;
	thepid = task_pid_vnr(target);
	spin_unlock(&target->runb_lock);

	printk("STARVE: PID is %d runb is now %d\n", thepid, runb);

	put_task_struct(target);
	return 0;
}

asmlinkage long sys_feed(pid_t pid)
{
	struct task_struct *target, *waker;
	pid_t thepid;
	int runb;
	unsigned long flags;
	wait_queue_t *curr, *next;

	int before = 0, after = 0;

	/* Look for other process */
	rcu_read_lock();
	target = find_task_by_vpid(pid);
	if (!target) {
		rcu_read_unlock();
		return -ESRCH;
	}

	/* Take reference */
	get_task_struct(target);
	rcu_read_unlock();

	spin_lock(&target->runb_lock);
	target->runb = 1;
	runb = target->runb;
	thepid = task_pid_vnr(target);

#if 1
	/* Wake up queue */
	spin_lock_irqsave(&target->testwq.lock, flags);
	list_for_each_entry_safe(curr, next, &target->testwq.task_list, task_list) {
		waker = curr->private;
		list_del(&curr->task_list);
		curr->func(curr, TASK_NORMAL, 0, 0);
		before++;
		thepid = task_pid_vnr(waker);
	}
	list_for_each_entry_safe(curr, next, &target->testwq.task_list, task_list) {
		after++;
	}
	spin_unlock_irqrestore(&target->testwq.lock, flags);
#endif
	spin_unlock(&target->runb_lock);

	printk("FEED: PID is %d runb is now %d BEFORE %d AFTER %d\n", thepid, runb, before, after);

	put_task_struct(target);
	return 0;
}

asmlinkage long sys_add_reserve_to_child_list(int reserve_id, unsigned int capabilities)
{
	struct task_struct *group_leader;
	struct cinder_reserve_process_link *link = NULL, *current_link, *clink = NULL;

	group_leader = current->group_leader;
	down(&group_leader->cinder_lock);

	/* Check whether we have access to this reserve */	
	list_for_each_entry(current_link, &group_leader->reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			link = current_link;
			break;
		}
	}
	/* If link is NULL, then we didn't have access to the reserve anyways */
	if (!link) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Now check if it is in the list already */
	list_for_each_entry(current_link, &current->child_create_reserves, process_list) {
		if (current_link->reserve->id == reserve_id) {
			/* Found it! */
			clink = current_link;
			break;
		}
	}

	/* If it is present, return success */
	if (clink) {
		up(&group_leader->cinder_lock);
		return 0;
	}

	/* We must add it to the list */
	clink = kmalloc(sizeof(*clink), GFP_KERNEL);
	if (!clink) {
		up(&group_leader->cinder_lock);
		return -ENOMEM;
	}


	/* Allocated the link, add it to the list */
	cinder_add_reserve_to_child_list(link, 
					 clink, 
					 current, 
					 group_leader, 
					 capabilities & link->capabilities);

	up(&group_leader->cinder_lock);
	return 0;
}

asmlinkage long sys_del_reserve_from_child_list(int reserve_id)
{
	int ret;
	struct task_struct *group_leader = current->group_leader;

	down(&group_leader->cinder_lock);
	ret = cinder_remove_reserve_from_child_list_by_id(reserve_id, current);
	up(&group_leader->cinder_lock);

	return ret;
}

asmlinkage long sys_num_child_list_reserves(void)
{
	long num_reserves;
	struct task_struct *group_leader = current->group_leader;

	down(&group_leader->cinder_lock);
	num_reserves = current->num_child_reserves;
	up(&group_leader->cinder_lock);

	return num_reserves;
}

asmlinkage int sys_get_child_list_reserve(long index)
{
	long reserve_id;
	long num_reserves, current_reserve = 0;
	struct task_struct *group_leader = current->group_leader;
	struct cinder_reserve_process_link *link = NULL, *current_link;

	if (index < 0)
		return -EINVAL;

	down(&group_leader->cinder_lock);
	num_reserves = current->num_child_reserves;

	if (index >= num_reserves) {
		up(&group_leader->cinder_lock);
		return -EINVAL;
	}

	/* Iterate our way over */
	list_for_each_entry(current_link,
		            &current->child_create_reserves,
			    process_list) {
		if (current_reserve == index) {
			link = current_link;
			break;
		}
		current_reserve++;
	}

	if (!link)
		BUG();

	reserve_id = link->reserve->id;
	up(&group_leader->cinder_lock);

	return reserve_id;
}

asmlinkage int sys_root_reserve_id()
{
	return root_reserve.id; // No need to lock, this is constant
}

#endif /* ifdef CONFIG_CINDER */

