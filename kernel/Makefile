#
# Makefile for the linux kernel.
#

obj-y     = sched.o fork.o exec_domain.o panic.o printk.o \
	    cpu.o exit.o itimer.o time.o softirq.o resource.o \
	    sysctl.o capability.o ptrace.o timer.o user.o \
	    signal.o sys.o kmod.o workqueue.o pid.o \
	    rcupdate.o extable.o params.o posix-timers.o \
	    kthread.o wait.o kfifo.o sys_ni.o posix-cpu-timers.o mutex.o \
	    hrtimer.o rwsem.o nsproxy.o srcu.o semaphore.o \
	    notifier.o ksysfs.o pm_qos_params.o sched_clock.o cred.o \
	    async.o

ifdef CONFIG_FUNCTION_TRACER
# Do not trace debug files and internal ftrace files
CFLAGS_REMOVE_lockdep.o = -pg
CFLAGS_REMOVE_lockdep_proc.o = -pg
CFLAGS_REMOVE_mutex-debug.o = -pg
CFLAGS_REMOVE_rtmutex-debug.o = -pg
CFLAGS_REMOVE_cgroup-debug.o = -pg
CFLAGS_REMOVE_sched_clock.o = -pg
endif

obj-$(CONFIG_CINDER) += cinder.o

obj-$(CONFIG_FREEZER) += freezer.o
obj-$(CONFIG_PROFILING) += profile.o
obj-$(CONFIG_SYSCTL_SYSCALL_CHECK) += sysctl_check.o
obj-$(CONFIG_STACKTRACE) += stacktrace.o
obj-y += time/
obj-$(CONFIG_DEBUG_MUTEXES) += mutex-debug.o
obj-$(CONFIG_LOCKDEP) += lockdep.o
ifeq ($(CONFIG_PROC_FS),y)
obj-$(CONFIG_LOCKDEP) += lockdep_proc.o
endif
obj-$(CONFIG_FUTEX) += futex.o
ifeq ($(CONFIG_COMPAT),y)
obj-$(CONFIG_FUTEX) += futex_compat.o
endif
obj-$(CONFIG_RT_MUTEXES) += rtmutex.o
obj-$(CONFIG_DEBUG_RT_MUTEXES) += rtmutex-debug.o
obj-$(CONFIG_RT_MUTEX_TESTER) += rtmutex-tester.o
obj-$(CONFIG_GENERIC_ISA_DMA) += dma.o
obj-$(CONFIG_USE_GENERIC_SMP_HELPERS) += smp.o
ifneq ($(CONFIG_SMP),y)
obj-y += up.o
endif
obj-$(CONFIG_SMP) += spinlock.o
obj-$(CONFIG_DEBUG_SPINLOCK) += spinlock.o
obj-$(CONFIG_PROVE_LOCKING) += spinlock.o
obj-$(CONFIG_UID16) += uid16.o
obj-$(CONFIG_MODULES) += module.o
obj-$(CONFIG_KALLSYMS) += kallsyms.o
obj-$(CONFIG_PM) += power/
obj-$(CONFIG_FREEZER) += power/
obj-$(CONFIG_BSD_PROCESS_ACCT) += acct.o
obj-$(CONFIG_KEXEC) += kexec.o
obj-$(CONFIG_BACKTRACE_SELF_TEST) += backtracetest.o
obj-$(CONFIG_COMPAT) += compat.o
obj-$(CONFIG_CGROUPS) += cgroup.o
obj-$(CONFIG_CGROUP_DEBUG) += cgroup_debug.o
obj-$(CONFIG_CGROUP_FREEZER) += cgroup_freezer.o
obj-$(CONFIG_CPUSETS) += cpuset.o
obj-$(CONFIG_CGROUP_NS) += ns_cgroup.o
obj-$(CONFIG_UTS_NS) += utsname.o
obj-$(CONFIG_USER_NS) += user_namespace.o
obj-$(CONFIG_PID_NS) += pid_namespace.o
obj-$(CONFIG_IKCONFIG) += configs.o
obj-$(CONFIG_RESOURCE_COUNTERS) += res_counter.o
obj-$(CONFIG_STOP_MACHINE) += stop_machine.o
obj-$(CONFIG_KPROBES_SANITY_TEST) += test_kprobes.o
obj-$(CONFIG_AUDIT) += audit.o auditfilter.o
obj-$(CONFIG_AUDITSYSCALL) += auditsc.o
obj-$(CONFIG_AUDIT_TREE) += audit_tree.o
obj-$(CONFIG_KPROBES) += kprobes.o
obj-$(CONFIG_KGDB) += kgdb.o
obj-$(CONFIG_DETECT_SOFTLOCKUP) += softlockup.o
obj-$(CONFIG_GENERIC_HARDIRQS) += irq/
obj-$(CONFIG_SECCOMP) += seccomp.o
obj-$(CONFIG_RCU_TORTURE_TEST) += rcutorture.o
obj-$(CONFIG_CLASSIC_RCU) += rcuclassic.o
obj-$(CONFIG_TREE_RCU) += rcutree.o
obj-$(CONFIG_PREEMPT_RCU) += rcupreempt.o
obj-$(CONFIG_TREE_RCU_TRACE) += rcutree_trace.o
obj-$(CONFIG_PREEMPT_RCU_TRACE) += rcupreempt_trace.o
obj-$(CONFIG_RELAY) += relay.o
obj-$(CONFIG_SYSCTL) += utsname_sysctl.o
obj-$(CONFIG_TASK_DELAY_ACCT) += delayacct.o
obj-$(CONFIG_TASKSTATS) += taskstats.o tsacct.o
obj-$(CONFIG_MARKERS) += marker.o
obj-$(CONFIG_TRACEPOINTS) += tracepoint.o
obj-$(CONFIG_LATENCYTOP) += latencytop.o
obj-$(CONFIG_HAVE_GENERIC_DMA_COHERENT) += dma-coherent.o
obj-$(CONFIG_FUNCTION_TRACER) += trace/
obj-$(CONFIG_TRACING) += trace/
obj-$(CONFIG_SMP) += sched_cpupri.o

ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
# According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
# needed for x86 only.  Why this used to be enabled for all architectures is beyond
# me.  I suspect most platforms don't need this, but until we know that for sure
# I turn this off for IA-64 only.  Andreas Schwab says it's also needed on m68k
# to get a correct value for the wait-channel (WCHAN in ps). --davidm
CFLAGS_sched.o := $(PROFILING) -fno-omit-frame-pointer
endif

$(obj)/configs.o: $(obj)/config_data.h

# config_data.h contains the same information as ikconfig.h but gzipped.
# Info from config_data can be extracted from /proc/config*
targets += config_data.gz
$(obj)/config_data.gz: .config FORCE
	$(call if_changed,gzip)

quiet_cmd_ikconfiggz = IKCFG   $@
      cmd_ikconfiggz = (echo "static const char kernel_config_data[] = MAGIC_START"; cat $< | scripts/bin2c; echo "MAGIC_END;") > $@
targets += config_data.h
$(obj)/config_data.h: $(obj)/config_data.gz FORCE
	$(call if_changed,ikconfiggz)

$(obj)/time.o: $(obj)/timeconst.h

quiet_cmd_timeconst  = TIMEC   $@
      cmd_timeconst  = $(PERL) $< $(CONFIG_HZ) > $@
targets += timeconst.h
$(obj)/timeconst.h: $(src)/timeconst.pl FORCE
	$(call if_changed,timeconst)
