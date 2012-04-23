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
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include <linux/in.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include "pidmonitor.h"
#include "db_monitor.h"

static struct rb_root db;

/* returns NULL if there isn't that port int the tree
*/
static int is_equal_packet_info(struct packet_info *pi,
		struct port_info *info)
{

	struct local_addresses_list *tmp = NULL;
	struct local_addresses_list *address = NULL;
	struct list_head *pos = NULL;

	switch (pi->protocol) {
	case IPPROTO_TCP:
		if (info->tcp)
			tmp = info->tcp;
		break;
	case IPPROTO_UDP:
		if (info->udp)
			tmp = info->udp;
		break;
	default:
		return 0;
	}

	if (!tmp)
		return 0;

	list_for_each(pos, &(tmp->list)) {
		address = list_entry(pos, struct local_addresses_list, list);
		if (pi->address == address->address && pi->pid == address->pid)
			return 1;
	}

	return 0;
}

struct port_info *__monitor_search(struct rb_root *root, struct packet_info *pi)
{
	struct rb_node *node = root->rb_node;
	struct port_info *data = NULL;

	while (node) {
		data = container_of(node, struct port_info, node);

		if (pi->port < data->port)
			node = node->rb_left;
		else
			if (pi->port > data->port)
				node = node->rb_right;
			else
				if (pi->port == data->port) {
					if (is_equal_packet_info(pi, data) != 0)
						return data;
					else
						return NULL;
				} else
					return NULL;
	}
	return NULL;
}

struct port_info *monitor_search(struct packet_info *pi)
{
	return __monitor_search(&db, pi);
}

static int add_address(struct packet_info *lpi, struct local_addresses_list *tmp,
		int *list_counter, int pid)
{
	struct local_addresses_list *address = NULL;
	struct list_head *pos = NULL;
	struct local_addresses_list *node = NULL;

	list_for_each(pos, &(tmp->list)) {
		address = list_entry(pos, struct local_addresses_list, list);
		if (lpi->address == address->address) {
			address->counter++;
			address->pid = pid;
			return 1;
		}
	}

	node = kmalloc(sizeof(*node), GFP_KERNEL);

	if (!node)
		return -1;

	node->address = lpi->address;
	node->counter = 1;

	list_add(&(node->list), &(tmp->list));
	(*list_counter)++;
	node->pid = pid;

	return 1;
}

static int insert_address(struct packet_info *lpi, struct port_info *port_info)
{

	switch (lpi->protocol) {
	case IPPROTO_TCP:
		if (!(port_info->tcp)) {
			port_info->tcp = kmalloc(sizeof(struct local_addresses_list), GFP_KERNEL);

			if (!port_info->tcp)
				return -1;

			INIT_LIST_HEAD(&((port_info->tcp)->list));
			port_info->tcp->counter = 0;
		}

		if (lpi->address == 0) {
			struct local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos, &(local_list->list)) {
				struct packet_info pi;
				address = list_entry(pos, struct local_addresses_list, list);
				pi.address = address->address;
				add_address(&pi, port_info->tcp, &(port_info->tcp_list_counter), lpi->pid);
			}
		} else {
			add_address(lpi, port_info->tcp, &(port_info->tcp_list_counter), lpi->pid);
		}

		break;
	case IPPROTO_UDP:
		if (!(port_info->udp)) {
			port_info->udp = kmalloc(sizeof(struct local_addresses_list), GFP_KERNEL);
			if (!port_info->udp)
				return -1;
			INIT_LIST_HEAD(&((port_info->udp)->list));
			port_info->udp->counter = 0;
		}
		if (lpi->address == 0) {
			struct local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos, &(local_list->list)) {
				struct packet_info pi;
				address = list_entry(pos, struct local_addresses_list, list);
				pi.address = address->address;
				add_address(&pi, port_info->udp, &(port_info->udp_list_counter), lpi->pid);
			}
		} else {
			add_address(lpi, port_info->udp, &(port_info->udp_list_counter), lpi->pid);
		}
		break;
	default:
		return -1;
	}

	return 0;
}

static struct port_info *create_packet_info(struct packet_info *lpi)
{
	struct port_info *pi = NULL;
	pi = kmalloc(sizeof(*pi), GFP_KERNEL);

	if (!pi)
		return NULL;

	pi->port = lpi->port;
	pi->tcp = NULL;
	pi->tcp_list_counter = 0;
	pi->udp = NULL;
	pi->udp_list_counter = 0;

	insert_address(lpi, pi);

	return pi;
}

int __monitor_insert(struct rb_root *root, struct packet_info *lpi)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct port_info *port = NULL;

	while (*new) {
		struct port_info *this = container_of(*new, struct port_info, node);

		parent = *new;
		if (lpi->port < this->port) {
			new = &((*new)->rb_left);
		} else
			if (lpi->port > this->port) {
				new = &((*new)->rb_right);
			} else {
				insert_address(lpi, this);
				return 1;
			}
	}
	port = create_packet_info(lpi);
	if (!port)
		return -1;

	rb_link_node(&port->node, parent, new);
	rb_insert_color(&port->node, root);

	return 1;
}

int monitor_insert(struct packet_info *lpi)
{
	return __monitor_insert(&db, lpi);
}

int decrement_address(struct packet_info *lpi,
		struct local_addresses_list *protocol, int *list_counter)
{
	struct local_addresses_list *address = NULL;
	struct list_head *pos = NULL, *q = NULL;

	list_for_each_safe(pos, q, &(protocol->list)) {
		address = list_entry(pos, struct local_addresses_list, list);
		if (lpi->address == address->address) {
			(address->counter)--;
			if (address->counter <= 0) {
				list_del(pos);
				kfree(address);
				(*(list_counter))--;
			}
			return 1;
		}
	}
	return 0;
}

static void remove_address_from_node(struct port_info *pi, struct packet_info *lpi)
{

	switch (lpi->protocol) {
	case IPPROTO_TCP:
		if (lpi->address) {
			decrement_address(lpi, pi->tcp, &(pi->tcp_list_counter));
		} else {
			struct local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos, &(local_list->list)) {
				struct packet_info aux;
				address = list_entry(pos, struct local_addresses_list, list);
				aux.address = address->address;
				decrement_address(&aux, pi->tcp, &(pi->tcp_list_counter));
			}
		}
		if (pi->tcp_list_counter == 0) {
			kfree(pi->tcp);
			pi->tcp = NULL;
		}
		break;

	case IPPROTO_UDP:
		if (lpi->address) {
			decrement_address(lpi, pi->udp, &(pi->udp_list_counter));
		} else {
			struct local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos, &(local_list->list)) {
				struct packet_info aux;
				address = list_entry(pos, struct local_addresses_list, list);
				aux.address = address->address;
				decrement_address(&aux, pi->udp, &(pi->udp_list_counter));
			}

		}
		if (pi->udp_list_counter == 0) {
			kfree(pi->udp);
			pi->udp = NULL;
		}
		break;
	default:
		return;
	}
}

void __monitor_erase(struct rb_root *root, struct packet_info *pi)
{
	struct port_info *data = __monitor_search(root, pi);

	if (data) {
		remove_address_from_node(data, pi);

		if ((!data->tcp) && !(data->udp)) {
			rb_erase(&data->node, root);
			kfree(data);
		}
	}
}

void monitor_erase(struct packet_info *pi)
{
	__monitor_erase(&db, pi);
}

static void clear_node_info(struct port_info *pi)
{
	struct local_addresses_list *tmp = NULL;
	struct list_head *pos = NULL, *q = NULL;

	if (pi->tcp_list_counter > 0 && pi->tcp != NULL) {
		struct local_addresses_list *aux = pi->tcp;
		list_for_each_safe(pos, q, &(aux->list)) {
			tmp = list_entry(pos, struct local_addresses_list, list);
			list_del(pos);
			kfree(tmp);
		}
		pi->tcp_list_counter = 0;
		kfree(pi->tcp);
	}

	if (pi->udp_list_counter > 0 && pi->udp != NULL) {
		struct local_addresses_list *aux = pi->udp;
		list_for_each_safe(pos, q, &(aux->list))
		{
			tmp = list_entry(pos, struct local_addresses_list, list);
			list_del(pos);
			kfree(tmp);
		}
		pi->udp_list_counter = 0;
		kfree(pi->udp);
	}
}

void clear_all_info(struct rb_root *root)
{
	struct rb_node *node = NULL, *next_node = NULL;
	struct port_info *p = NULL;

	node = rb_first(root);
	while (node) {
		next_node = rb_next(node);
		p = rb_entry(node, struct port_info, node);
		clear_node_info(p);

		rb_erase(node, root);
		kfree(p);
		p = NULL;
		node = next_node;
	}
}

static void __print_addresses_list(struct seq_file *m, struct local_addresses_list *list)
{
	struct local_addresses_list *tmp = NULL;
	struct list_head *pos = NULL, *q = NULL;

	struct local_addresses_list *aux = list;
	list_for_each_safe(pos, q, &(aux->list)) {
		tmp = list_entry(pos, struct local_addresses_list, list);
		/*seq_printf(m, "address: %d.%d.%d.%d\t",
		 * 		NIPQUAD(tmp->address));*/
	}
}

static void __print_node(struct seq_file *m, struct port_info *p)
{
	seq_printf(m, "Port %d\n", p->port);
	if (p->tcp != NULL) {
		seq_printf(m, "tcp list:\n");
		__print_addresses_list(m, p->tcp);
	}
	if (p->udp != NULL) {
		seq_printf(m, "udp list:\n");
		__print_addresses_list(m, p->udp);
	}
}

void print_repository(struct seq_file *m, struct rb_root *root)
{
	struct rb_node *node = NULL, *next_node = NULL;
	struct port_info *p = NULL;

	node = rb_first(root);
	while (node) {
		next_node = rb_next(node);
		p = rb_entry(node, struct port_info, node);
		/*
		   clear_node_info(p);
		   rb_erase(node, root);
		   kfree(p);
		   p = NULL;
		   */
		__print_node(m, p);
		seq_printf(m, "\n");
		node = next_node;
	}
}

void init_db_monitor(void)
{
}

void exit_db_monitor(void)
{
	clear_all_info(&db);
}
