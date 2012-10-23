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

#ifndef _PORTSDB_MONITOR_H
#define _PORTSDB_MONITOR_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>

#include "pidmonitor.h"

struct port_info {
	struct rb_node node;
	u16 port;
	struct local_addresses_list *udp;
	struct local_addresses_list *tcp;
	int tcp_list_counter;
	int udp_list_counter;
};

struct port_info *monitor_search(struct packet_info *pi);
int monitor_insert(struct packet_info *lpi);
void monitor_erase(struct packet_info *pi);
void clear_all_info(struct rb_root *root);

void init_db_monitor(void);
void exit_db_monitor(void);

#endif /* _PORTSDB_MONITOR_H */
