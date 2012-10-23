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
#ifndef _PID_MONITOR_H
#define _PID_MONITOR_H

#include <linux/types.h>
#include <linux/fs.h>
#include <net/net_namespace.h>
#include <linux/list.h>

struct packet_info {
	u8 protocol;
	u16 port;
	u32 address;
	int pid;
};

struct local_addresses_list {
	struct list_head list;
	u32 address;
	unsigned int pid;
	int counter;
};

extern struct local_addresses_list *local_list;
extern struct socket *sockfd_lookup(int fd, int *err);
int get_local_packet_info_from_fd(unsigned int fd, struct packet_info *pi);
int get_local_packet_info_from_file(struct file *file, struct packet_info *pi);
struct local_addresses_list *list_all_devices_address(void);
int remove_local_addresses_list(struct local_addresses_list *list);
extern struct net inet;

int init_process_filter_function_fn(struct filter_function_struct *ffs);
void init_repo_task(int pidnr);

#endif /* _PID_MONITOR_H */
