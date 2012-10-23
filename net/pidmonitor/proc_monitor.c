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
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <linux/inetdevice.h>


#include "pidmonitor.h"

static void get_inet_sock_param(struct inet_sock *inetsock, struct packet_info *pi)
{
	pi->port = inetsock->inet_num;
	pi->protocol = ((struct sock *)inetsock)->sk_protocol;

	if (pi->port == ntohs(inetsock->inet_sport)) {
		if (!inetsock->inet_rcv_saddr)
			pi->address = inetsock->inet_saddr;
		else
			pi->address = inetsock->inet_rcv_saddr;

	} else
		pi->address = inetsock->inet_daddr;

	pi->address = ntohl(pi->address);
}

int get_local_packet_info_from_file(struct file *file, struct packet_info *pi)
{
	struct socket *socket = NULL;
	short type;
	unsigned short family;
	int err = 0;

	if (file != NULL) {
		struct dentry *dentry;
		struct inode *d_inode;
		dentry = file->f_dentry;
		if (dentry != NULL) {
			d_inode = dentry->d_inode;
			if (S_ISSOCK(d_inode->i_mode)) {
				socket = file->private_data;
				if (socket == NULL) {
					err = -5;
					goto out;
				}
				type = socket->type;
				if (socket->sk == NULL) {
					err = -6;
					goto out;
				}
				family = socket->sk->__sk_common.skc_family;
				if (family != AF_INET) {
					err = -4;
					goto out;
				} else {
					get_inet_sock_param((struct inet_sock *)(socket->sk), pi);
					err = 0;
				}
			} else {
				err = -1;
			}
		} else {
			err = -2;
		}
	} else {
		err = -3;
	}
out:
	return err;

}

int get_local_packet_info_from_fd(unsigned int fd, struct packet_info *pi)
{
	struct file *f = fget(fd);
	int ret = -1;

	if (f != NULL) {
		ret = get_local_packet_info_from_file(f, pi);
		fput(f);
		return ret;
	}
	return -3;
}
