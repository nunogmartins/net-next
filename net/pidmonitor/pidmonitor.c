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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <linux/inetdevice.h>

#include "pidmonitor.h"
#include "filter.h"
#include "syscalls_monitor.h"
#include "multi_pid_repository.h"
#include "db_monitor.h"
#include "debugfs_monitor.h"
#include "inject_monitor.h"

struct local_addresses_list *local_list;

struct local_addresses_list *list_all_devices_address(void)
{
	struct net_device *dev;
	struct net *net = &init_net;
	struct local_addresses_list *list = NULL;
	struct local_addresses_list *tmp = NULL;

	list = kmalloc(sizeof(*list), GFP_KERNEL);
	INIT_LIST_HEAD(&(list->list));

	for_each_netdev(net, dev) {
		if (dev->ip_ptr) {
			struct in_device *in4 = dev->ip_ptr;
			struct in_ifaddr *addr;
			for (addr = in4->ifa_list; addr; addr = addr->ifa_next) {
				tmp = kmalloc(sizeof(*tmp), GFP_KERNEL);
				tmp->address = ntohl(addr->ifa_address);
				list_add(&(tmp->list), &(list->list));
			}
		}
	}
	return list;
}

int remove_local_addresses_list(struct local_addresses_list *list)
{
	struct local_addresses_list *tmp;
	struct list_head *pos = NULL, *q = NULL;

	list_for_each_safe(pos, q, &(list->list)) {
		tmp = list_entry(pos, struct local_addresses_list, list);
		list_del(pos);
		kfree(tmp);
	}

	return 0;
}

static int __init monitor_init(void)
{
	init_debugfs_monitor();
	init_syscalls_monitor();
	init_multi_repo();
	init_db_monitor();
	init_filter();
	init_inject_monitor();

	local_list = list_all_devices_address();
	return 0;
}

static void __exit monitor_exit(void)
{
	int ret = -1;
	exit_debugfs_monitor();
	exit_multi_repo();
	exit_db_monitor();
	exit_filter();
	exit_syscalls_monitor();
	exit_inject_monitor();

	ret = remove_local_addresses_list(local_list);
	if (ret == 0)
		kfree(local_list);
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");
