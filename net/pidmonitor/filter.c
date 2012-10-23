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

/*
 * Linux Socket Filter - Kernel level socket filtering
 *
 * Author:
 *     Jay Schulist <jschlst@samba.org>
 *
 * Based on the design of:
 *     - The Berkeley Packet Filter
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Andi Kleen - Fix a few bad bugs and races.
 * Kris Katterjohn - Added many additional checks in sk_chk_filter()
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/gfp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <asm/unaligned.h>
#include <linux/filter.h>
#include <linux/reciprocal_div.h>
#include <linux/ratelimit.h>

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/socket.h>

#include <linux/skbuff.h>
#include <linux/filter.h>
#include <asm/unaligned.h>

#include "pidmonitor.h"
#include "db_monitor.h"

/* No hurry in this branch */
static void *__load_pointer(const struct sk_buff *skb, int k, unsigned int size)
{
	u8 *ptr = NULL;

	if (k >= SKF_NET_OFF)
		ptr = skb_network_header(skb) + k - SKF_NET_OFF;
	else if (k >= SKF_LL_OFF)
		ptr = skb_mac_header(skb) + k - SKF_LL_OFF;

	if (ptr >= skb->head && ptr + size <= skb_tail_pointer(skb))
		return ptr;
	return NULL;
}

static inline void *load_pointer(const struct sk_buff *skb, int k,
				 unsigned int size, void *buffer)
{
	if (k >= 0)
		return skb_header_pointer(skb, k, size, buffer);
	return __load_pointer(skb, k, size);
}

int dynamic_filter(const struct sk_buff *skb, const int pid);

unsigned int process_packets(const struct sk_buff *skb,
			   const struct sock_filter *fentry)
{
	void *ptr;
	u32 A = 0;			/* Accumulator */
	u32 X = 0;			/* Index Register */
	u32 mem[BPF_MEMWORDS];		/* Scratch Memory Store */
	u32 tmp;
	int k;
	/*
	 * Process array of filter instructions.
	 */
	for (;; fentry++) {
#if defined(CONFIG_X86_32)
#define	K (fentry->k)
#else
		const u32 K = fentry->k;
#endif

		switch (fentry->code) {
		case BPF_S_ALU_ADD_X:
			A += X;
			continue;
		case BPF_S_ALU_ADD_K:
			A += K;
			continue;
		case BPF_S_ALU_SUB_X:
			A -= X;
			continue;
		case BPF_S_ALU_SUB_K:
			A -= K;
			continue;
		case BPF_S_ALU_MUL_X:
			A *= X;
			continue;
		case BPF_S_ALU_MUL_K:
			A *= K;
			continue;
		case BPF_S_ALU_DIV_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;
		case BPF_S_ALU_DIV_K:
			A = reciprocal_divide(A, K);
			continue;
		case BPF_S_ALU_AND_X:
			A &= X;
			continue;
		case BPF_S_ALU_AND_K:
			A &= K;
			continue;
		case BPF_S_ALU_OR_X:
			A |= X;
			continue;
		case BPF_S_ALU_OR_K:
			A |= K;
			continue;
		case BPF_S_ALU_LSH_X:
			A <<= X;
			continue;
		case BPF_S_ALU_LSH_K:
			A <<= K;
			continue;
		case BPF_S_ALU_RSH_X:
			A >>= X;
			continue;
		case BPF_S_ALU_RSH_K:
			A >>= K;
			continue;
		case BPF_S_ALU_NEG:
			A = -A;
			continue;
		case BPF_S_JMP_JA:
			fentry += K;
			continue;
		case BPF_S_JMP_JGT_K:
			fentry += (A > K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGE_K:
			fentry += (A >= K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JEQ_K:
			fentry += (A == K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JSET_K:
			fentry += (A & K) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGT_X:
			fentry += (A > X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JGE_X:
			fentry += (A >= X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JEQ_X:
			fentry += (A == X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_JMP_JSET_X:
			fentry += (A & X) ? fentry->jt : fentry->jf;
			continue;
		case BPF_S_LD_W_ABS:
			k = K;
load_w:
			ptr = load_pointer(skb, k, 4, &tmp);
			if (ptr != NULL) {
				A = get_unaligned_be32(ptr);
				continue;
			}
			return 0;
		case BPF_S_LD_H_ABS:
			k = K;
load_h:
			ptr = load_pointer(skb, k, 2, &tmp);
			if (ptr != NULL) {
				A = get_unaligned_be16(ptr);
				continue;
			}
			return 0;
		case BPF_S_LD_B_ABS:
			k = K;
load_b:
			ptr = load_pointer(skb, k, 1, &tmp);
			if (ptr != NULL) {
				A = *(u8 *)ptr;
				continue;
			}
			return 0;
		case BPF_S_LD_W_LEN:
			A = skb->len;
			continue;
		case BPF_S_LDX_W_LEN:
			X = skb->len;
			continue;
		case BPF_S_LD_W_IND:
			k = X + K;
			goto load_w;
		case BPF_S_LD_H_IND:
			k = X + K;
			goto load_h;
		case BPF_S_LD_B_IND:
			k = X + K;
			goto load_b;
		case BPF_S_LDX_B_MSH:
			ptr = load_pointer(skb, K, 1, &tmp);
			if (ptr != NULL) {
				X = (*(u8 *)ptr & 0xf) << 2;
				continue;
			}
			return 0;
		case BPF_S_LD_IMM:
			A = K;
			continue;
		case BPF_S_LDX_IMM:
			X = K;
			continue;
		case BPF_S_LD_MEM:
			A = mem[K];
			continue;
		case BPF_S_LDX_MEM:
			X = mem[K];
			continue;
		case BPF_S_MISC_TAX:
			X = A;
			continue;
		case BPF_S_MISC_TXA:
			A = X;
			continue;
		case BPF_S_MISC_PROC:
			A = dynamic_filter(skb, ((fentry+1)->k)) ? ((fentry+1)->k) : 0;
			continue;
		case BPF_S_RET_K:
			return K;
		case BPF_S_RET_A:
			return A;
		case BPF_S_ST:
			mem[K] = A;
			continue;
		case BPF_S_STX:
			mem[K] = X;
			continue;
		case BPF_S_ANC_PROTOCOL:
			A = ntohs(skb->protocol);
			continue;
		case BPF_S_ANC_PKTTYPE:
			A = skb->pkt_type;
			continue;
		case BPF_S_ANC_IFINDEX:
			if (!skb->dev)
				return 0;
			A = skb->dev->ifindex;
			continue;
		case BPF_S_ANC_MARK:
			A = skb->mark;
			continue;
		case BPF_S_ANC_QUEUE:
			A = skb->queue_mapping;
			continue;
		case BPF_S_ANC_HATYPE:
			if (!skb->dev)
				return 0;
			A = skb->dev->type;
			continue;
		case BPF_S_ANC_RXHASH:
			A = skb->rxhash;
			continue;
		case BPF_S_ANC_CPU:
			A = raw_smp_processor_id();
			continue;
		case BPF_S_ANC_NLATTR: {
			struct nlattr *nla;

			if (skb_is_nonlinear(skb))
				return 0;
			if (A > skb->len - sizeof(struct nlattr))
				return 0;

			nla = nla_find((struct nlattr *)&skb->data[A],
				       skb->len - A, X);
			if (nla)
				A = (void *)nla - (void *)skb->data;
			else
				A = 0;
			continue;
		}
		case BPF_S_ANC_NLATTR_NEST: {
			struct nlattr *nla;

			if (skb_is_nonlinear(skb))
				return 0;
			if (A > skb->len - sizeof(struct nlattr))
				return 0;

			nla = (struct nlattr *)&skb->data[A];
			if (nla->nla_len > A - skb->len)
				return 0;

			nla = nla_find_nested(nla, X);
			if (nla)
				A = (void *)nla - (void *)skb->data;
			else
				A = 0;
			continue;
		}
		default:
			WARN_RATELIMIT(1, "Unknown code:%u jt:%u tf:%u k:%u\n",
				       fentry->code, fentry->jt,
				       fentry->jf, fentry->k);
			return 0;
		}
	}

	return 0;
}


unsigned int process_filter_function(const struct sk_buff *skb,
		const struct sock_filter *filter, const int pid);

int init_process_filter_function_fn(struct filter_function_struct *ffs);

static struct filter_function ff = {
	.name = "process_packet_filter",
	.init_func = &init_process_filter_function_fn,
	.func = &process_packets
};

/* @pi must be allocated previously
 * @skb is the buffer passed to the filter
 */
static inline int get_packet_info(const struct sk_buff *skb,
	struct packet_info *src_pi, struct packet_info *dst_pi)
{
	u32 tmp;
	void *ptr;
	u32 X;

	ptr = skb_header_pointer(skb, 23, 1, &tmp);
	if (ptr != NULL) {
		src_pi->protocol = *(u8 *)ptr;
		dst_pi->protocol = *(u8 *)ptr;
	} else
		goto out;

	ptr = skb_header_pointer(skb, 26, 4, &tmp);
	if (ptr != NULL)
		src_pi->address = get_unaligned_be32(ptr);
	else
		goto out;

	ptr = skb_header_pointer(skb, 30, 4, &tmp);
	if (ptr != NULL)
		dst_pi->address = get_unaligned_be32(ptr);
	else
		goto out;

	ptr = skb_header_pointer(skb, 14, 1, &tmp);
	if (ptr != NULL) {
		X = (*(u8 *)ptr & 0xf) << 2;
		X += 14;
		ptr = skb_header_pointer(skb, X, 2, &tmp);
		if (ptr != NULL)
			src_pi->port = get_unaligned_be16(ptr);
		else
			goto out;

		X += 2;
		ptr = skb_header_pointer(skb, X, 2, &tmp);
		if (ptr != NULL)
			dst_pi->port = get_unaligned_be16(ptr);
		else
			goto out;
	} else
		goto out;

	return 0;

out:
	return -1;
}

int packet_belongs(struct packet_info *src_pi, struct packet_info *dst_pi)
{
	if ((src_pi->protocol == IPPROTO_TCP || src_pi->protocol == IPPROTO_UDP)) {
		if (monitor_search(src_pi))
			return src_pi->pid;

		if (monitor_search(dst_pi))
			return dst_pi->pid;
	}

	return 0;
}

int dynamic_filter(const struct sk_buff *skb, const int pid)
{
	void *ptr;
	u32 A;
	u32 tmp;
	int err = -ENODATA;

	ptr = skb_header_pointer(skb, 12, 2, &tmp);
	if (ptr != NULL) {
		A = get_unaligned_be16(ptr);
		if (A == 0x800) {
			struct packet_info dst_pi;
			struct packet_info src_pi;
			dst_pi.pid = pid;
			src_pi.pid = pid;
			if (!get_packet_info(skb, &src_pi, &dst_pi))
				return packet_belongs(&src_pi, &dst_pi);
		}
	}
	return err;
}

unsigned int process_filter_function(const struct sk_buff *skb,
					const struct sock_filter *filter, const int pid)
{
	return dynamic_filter(skb, pid);
}

int init_filter(void)
{
	register_filter_function(&ff);
	return 0;
}
void exit_filter(void)
{
	unregister_filter_function(&ff);
}
