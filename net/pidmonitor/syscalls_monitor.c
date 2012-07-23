/*
 * Packet Filtering System based on BPF / LSF
 *
 * Author: Nuno Martins <nuno.martins@caixamagica.pt>
 *
 * (c) Copyright Caixa Magica Software, LDA., 2012
 * (c) Copyright Universidade Nova de Lisboa, 2010-2011
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program;  if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */
#include <linux/ptrace.h>

#include <linux/module.h>
#include <linux/kprobes.h>

#include <net/sock.h>
#include <linux/string.h>
#include <net/inet_sock.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/list.h>

#include <linux/pid.h>
#include <asm-generic/errno.h>
#include <linux/socket.h>

#include <linux/bitmap.h>

#include "pidmonitor.h"
#include "multi_pid_repository.h"
#include "db_monitor.h"

#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include "debugfs_monitor.h"

pid_t pid = -1, ppid = -1, tgid = -1;
/*
 * Using a bitmap for fast search for
 * a process id
 */
static DECLARE_BITMAP(pid_table, 32768);
static struct dentry *syscalls_dir;
static struct stats {
} syscalls_stats;

void set_process_identifiers(pid_t lpid)
{
	pid = lpid;
	set_bit((int)lpid, pid_table);
}

int init_process_filter_function_fn(struct filter_function_struct *ffs)
{
	set_process_identifiers(ffs->pid);
	multi_repo_create(ffs->pid);
	init_repo_task(ffs->pid);
	try_module_get(THIS_MODULE);
	return 0;
}

void exit_process_filter_function_fn(struct filter_function_struct *ffs)
{
	/*
	 * clean stuff
	 */

	module_put(THIS_MODULE);
}
int kprobes_index;
#define TO_MONITOR(t) \
	do { \
		if (test_bit(t->pid, pid_table)) \
			goto monitor; \
		else { \
			my_data->fd = -1; \
			return 0; \
		} \
	} while (0)

#define NR_PROBES 7

struct kretprobe *kretprobes;

struct cell {
	int fd;
};

struct close_info {
	int fd;
	struct packet_info pi;
};

struct connect_extern_info {
	struct packet_info external;
	int fd;
};

static int sendto_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;

#ifdef CONFIG_X86_32
	int fd = regs->ax;
#else
	int fd = regs->di;
#endif
	struct cell *my_data = (struct cell *)ri->data;
	TO_MONITOR(task);

monitor:
	my_data->fd = fd;
	return 0;
}
static int sendto_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{

	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packet_info pi;
	int fd = my_data->fd;

	if (my_data->fd == -1)
		return 0;

	if (retval >= 0 || retval == -EAGAIN || retval == -EINPROGRESS || retval == -EALREADY) {
		pi.pid = ri->task->pid;
		if (!get_local_packet_info_from_fd(fd, &pi)) {
			struct multi_repo_node *t = multi_pid_search(ri->task->pid);
			if (t != NULL)
				__monitor_insert(&t->tree, &pi);
		}
	}
	return 0;
}

static int recvfrom_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct cell *my_data = (struct cell *)ri->data;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
#else
	int fd = regs->di;
#endif
	TO_MONITOR(task);

monitor:
	my_data->fd = fd;
	return 0;
}
static int recvfrom_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packet_info pi;
	int fd = my_data->fd;

	if (my_data->fd == -1)
		return 0;

	if (retval >= 0 || retval == -EAGAIN || retval == -EINPROGRESS) {
		pi.pid = ri->task->pid;
		if (!get_local_packet_info_from_fd(fd, &pi)) {
			struct multi_repo_node *t = multi_pid_search(ri->task->pid);
			if (t != NULL)
				__monitor_insert(&t->tree, &pi);
		}

	}

	return 0;
}

static int accept_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct cell *my_data = (struct cell *)ri->data;

	TO_MONITOR(task);

monitor:
	my_data->fd = 0;
	return 0;
}
static int accept_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packet_info pi;

	if (my_data->fd == -1)
		return 0;

	if (retval > 0) {
		pi.pid = ri->task->pid;
		if (!get_local_packet_info_from_fd(retval, &pi)) {
			struct multi_repo_node *t = multi_pid_search(ri->task->pid);
			if (t != NULL)
				__monitor_insert(&t->tree, &pi);
		}

	}

	return 0;
}

static int close_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct close_info *my_data = (struct close_info *)ri->data;

#ifdef CONFIG_X86_32
	struct file *filp = (struct file *)regs->bx;
#else
	struct file *filp = (struct file *)regs->si;
#endif

	int err = -1;
	TO_MONITOR(task);

monitor:

	err = get_local_packet_info_from_file(filp, &(my_data->pi));
	if (err >= 0)
		my_data->fd = -2;
	else
		my_data->fd = -1;

	return 0;
}

static int close_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct close_info *cI = (struct close_info *)ri->data;

	if (cI->fd == -1)
		return 0;

	if (retval == 0) {
		struct multi_repo_node *t = multi_pid_search(ri->task->pid);
		if (t != NULL)
			__monitor_erase(&t->tree, &(cI->pi));
	}
	return 0;
}

static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
#else
	int fd = regs->di;
#endif
	struct cell *my_data = (struct cell *)ri->data;
	TO_MONITOR(task);

monitor:
	my_data->fd = fd;
	return 0;
}

static int bind_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packet_info pi;
	int fd = my_data->fd;

	if (my_data->fd == -1)
		return 0;

	pi.pid = ri->task->pid;
	if (retval == 0 && !get_local_packet_info_from_fd(fd, &pi)) {
		struct multi_repo_node *t = multi_pid_search(ri->task->pid);
		if (t != NULL)
			__monitor_insert(&t->tree, &pi);
	}
	return 0;
}

static int connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct connect_extern_info *my_data = (struct connect_extern_info *)ri->data;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
	struct sockaddr_in *in = (struct sockaddr_in *)regs->dx;
#else
	int fd = regs->di;
	struct sockaddr_in *in = (struct sockaddr_in *)regs->si;
#endif
	TO_MONITOR(task);

monitor:
	my_data->fd = fd;

	if (!get_local_packet_info_from_fd(fd, &(my_data->external))) {
		struct multi_repo_node *t = multi_pid_search(ri->task->pid);
		my_data->external.address = ntohl(in->sin_addr.s_addr);
		my_data->external.port = ntohs(in->sin_port);
		(my_data->external).pid = task->pid;
		if (t != NULL)
			__monitor_insert(&t->tree, &(my_data->external));
	} else
		my_data->fd = -1;

	return 0;
}

static int connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct connect_extern_info *my_data = (struct connect_extern_info *)ri->data;
	int fd = my_data->fd;
	struct packet_info pi;

	if (fd == -1)
		return 0;

	if (retval == 0 || retval == -EINPROGRESS || retval == -EALREADY || retval == -EISCONN || retval == -EAGAIN) {
		struct multi_repo_node *t = multi_pid_search(ri->task->pid);
		if (t != NULL)
			__monitor_erase(&t->tree, &(my_data->external));
		pi.pid = ri->task->pid;
		if (!get_local_packet_info_from_fd(fd, &pi)) {
			if (t != NULL)
				__monitor_insert(&t->tree, &pi);
		}
	}

	return 0;
}

static int instantiationKRETProbe(struct kretprobe *kret,
				const char *function_name,
				kretprobe_handler_t func_handler,
				kretprobe_handler_t func_entry_handler,
				ssize_t data_size)
{
	int ret = -1;

	struct kprobe kp = {
		.symbol_name = function_name,
	};

	kret->kp = kp;
	kret->handler = func_handler;
	kret->entry_handler = func_entry_handler;
	kret->data_size	= data_size;
	kret->maxactive = 8;

	ret = register_kretprobe(kret);
	if (ret < 0)
		return -1;

	return ret;
}

static int syscalls_monitor_seq_show(struct seq_file *m, void *v)
{
	return 0;
}

static int syscalls_monitor_open(struct inode *inode, struct file *file)
{
	return single_open(file, syscalls_monitor_seq_show, inode->i_private);
}

static const struct file_operations syscalls_monitor_fops = {
	.open           = syscalls_monitor_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
	.owner          = THIS_MODULE,
};

/*
 * function called on module init to initialize kretprobes common to tcp and udp
 */

static int init_kretprobes_syscalls(void)
{
	int ret = 0;

	kretprobes = kmalloc(sizeof(*kretprobes) * NR_PROBES, GFP_KERNEL);

	if (!kretprobes)
		return -1;

	ret = instantiationKRETProbe((kretprobes+kprobes_index),
			"sys_bind", bind_ret_handler, bind_entry_handler,
			(ssize_t)sizeof(struct cell));
	debugfs_create_file("sys_bind", S_IRUSR, syscalls_dir, &syscalls_stats,
				&syscalls_monitor_fops);
	kprobes_index += 1;
	if (ret < 0)
		return -1;

	ret = instantiationKRETProbe((kretprobes+kprobes_index),
			"sys_connect", connect_ret_handler,
			connect_entry_handler,
			(ssize_t)sizeof(struct connect_extern_info));
	debugfs_create_file("sys_connect", S_IRUSR, syscalls_dir, &syscalls_stats,
				&syscalls_monitor_fops);
	kprobes_index += 1;
	if (ret < 0)
		return -1;

	ret = instantiationKRETProbe((kretprobes+kprobes_index),
			"sock_close", close_ret_handler, close_entry_handler,
			(ssize_t)sizeof(struct packet_info));
	debugfs_create_file("sock_close", S_IRUSR, syscalls_dir, &syscalls_stats,
				&syscalls_monitor_fops);
	kprobes_index += 1;
	if (ret < 0)
		return -1;

	ret = instantiationKRETProbe((kretprobes+kprobes_index),
			"sys_accept4", accept_ret_handler, accept_entry_handler,
			(ssize_t)sizeof(struct cell));
	debugfs_create_file("sys_accept4", S_IRUSR, syscalls_dir, &syscalls_stats,
				&syscalls_monitor_fops);
	kprobes_index += 1;
		if (ret < 0)
			return -1;

	ret = instantiationKRETProbe((kretprobes+kprobes_index),
			"sys_sendto", sendto_ret_handler, sendto_entry_handler,
			(ssize_t)sizeof(struct cell));
	debugfs_create_file("sys_sendto", S_IRUSR, syscalls_dir, &syscalls_stats,
				&syscalls_monitor_fops);
	kprobes_index += 1;
	if (ret < 0)
		return -1;

	ret = instantiationKRETProbe((kretprobes+kprobes_index),
			"sys_recvfrom", recvfrom_ret_handler,
			recvfrom_entry_handler, (ssize_t)sizeof(struct cell));
	debugfs_create_file("sys_recvfrom", S_IRUSR, syscalls_dir, &syscalls_stats,
				&syscalls_monitor_fops);
	kprobes_index += 1;
	if (ret < 0)
		return -1;

	return kprobes_index;
}

static void removeKprobe(int index)
{
	if ((kretprobes + index) != NULL)
		unregister_kretprobe((kretprobes + index));
}

static void destroy_kretprobes_syscalls(void)
{
	int i = -1;

	for (i = 0; i < kprobes_index ; i++)
		removeKprobe(i);

	if (kretprobes)
		kfree(kretprobes);
}

int init_syscalls_monitor(void)
{
	int ret = 0;
	syscalls_dir = syscalls_debug_monitor("syscalls");
	ret = init_kretprobes_syscalls();
	return ret;
}

void exit_syscalls_monitor(void)
{
	destroy_kretprobes_syscalls();
}
