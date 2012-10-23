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

#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/byteorder/generic.h>
#include <linux/uaccess.h>
#include <linux/filter.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/file.h>

#include "pidmonitor.h"
#include "db_monitor.h"

static void read_from_fdtable(struct task_struct *task)
{
	int fd;
	int max_fds;
	struct file *file;

	max_fds = task->files->fdt->max_fds;
	for (fd = 0; fd < max_fds ; fd++) {
		file = fcheck_files(task->files, fd);
		if (file) {
			struct packet_info pi;
			pi.pid = task->pid;
			if (!get_local_packet_info_from_file(file, &pi))
				monitor_insert(&pi);
		}
	}
}

static void init_tree(struct task_struct *task)
{

	if (task == NULL)
		return;

	rcu_read_lock();
	read_from_fdtable(task);
	rcu_read_unlock();
}

void init_repo_task(int pidnr)
{
	struct task_struct *task = NULL;
	struct pid *pid = find_get_pid(pidnr);
	rcu_read_lock();
	task = pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	rcu_read_unlock();
	init_tree(task);
}
