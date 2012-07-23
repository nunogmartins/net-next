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
#ifdef CONFIG_FILTER_FUNCTION

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/filter.h>
#include <net/sock.h>

static LIST_HEAD(filter_list);
static DEFINE_MUTEX(filter_list_mutex);

int register_filter_function(struct filter_function *ff)
{
	list_add(&(ff->list), &filter_list);

	return 0;
}
EXPORT_SYMBOL(register_filter_function);

static struct filter_function *find_filter_function_by_addr(void *addr)
{
	struct filter_function *ff;

	if (addr == sk_run_filter)
		return NULL;

	list_for_each_entry(ff, &filter_list, list) {
		if (ff->func == addr)
			return ff;
	}

	return NULL;
}
EXPORT_SYMBOL(find_filter_function_by_addr);

static struct filter_function *find_filter_function_by_name(const char *name)
{
	struct filter_function *ff;
	list_for_each_entry(ff, &filter_list, list) {
		if (strcmp(ff->name, name) == 0)
			return ff;
	}
	return NULL;
}
EXPORT_SYMBOL(find_filter_function_by_name);

int unregister_filter_function(struct filter_function *ff)
{
	list_del(&(ff->list));
	return 0;
}
EXPORT_SYMBOL(unregister_filter_function);

int attach_filter_function(struct filter_function_struct *ffs, struct sock *sk)
{
	struct filter_function *ff = NULL;
	struct sk_filter *old_fp;

	if (strcmp(ffs->name, "sk_run_filter") != 0)
		ff = find_filter_function_by_name(ffs->name);

	if (ff != NULL) {
		int ret;
		if (ff->init_func != NULL)
			ret = ff->init_func(ffs);

		if (ff->func != NULL) {
			old_fp = rcu_dereference_protected(sk->sk_filter,
					sock_owned_by_user(sk));
			if (detect_filter_function(old_fp))
				bpf_jit_free(old_fp);

			old_fp->bpf_func = ff->func;
			rcu_assign_pointer(sk->sk_filter, old_fp);
		}
	} else {
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(attach_filter_function);

int detach_filter_function(struct filter_function_struct *ffs, struct sock *sk)
{
	struct sk_filter *old_fp;
	struct filter_function *ff;

	old_fp = rcu_dereference_protected(sk->sk_filter,
			sock_owned_by_user(sk));

	ff = find_filter_function_by_addr(old_fp->bpf_func);
	if (ff != NULL) {
		ff->exit_func(ffs);
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL(detach_filter_function);

int detect_filter_function(struct sk_filter *fp)
{
	return find_filter_function_by_addr(fp->bpf_func) ? 0 : -1;
}
EXPORT_SYMBOL(detect_filter_function);
#endif
