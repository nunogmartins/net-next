/*
 * Author: Nuno Martins <nuno.martins@caixamagica.pt>
 *
 * (c) Copyright Caixa Magica Software, LDA., 2012
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
 * multi_pid_repository.c
 *
 *  Created on: Apr 23, 2012
 *      Author: nuno
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "multi_pid_repository.h"
#include "db_monitor.h"

static struct rb_root multi_repo_tree;

/*#ifdef REPO_DEBUG*/
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/module.h>

#include "debugfs_monitor.h"

static struct dentry *repo;

static int repo_monitor_seq_show(struct seq_file *m, void *v)
{
	struct multi_repo_node *multi_node = m->private;
	seq_printf(m, "repository file %d\n", multi_node->pid);
	print_repository(m, &multi_node->tree);
        return 0;
}

static int repo_monitor_open(struct inode *inode, struct file *file)
{
        return single_open(file, repo_monitor_seq_show, inode->i_private);
}

static const struct file_operations repo_monitor_fops = {
        .open           = repo_monitor_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release 	= single_release,
        .owner          = THIS_MODULE,
};

/*#endif*/

static struct multi_repo_node * __multi_pid_search(struct rb_root *root, pid_t pid)
{
	struct rb_node *node = root->rb_node;
	struct multi_repo_node *data = NULL;

	while (node) {
		data = container_of(node, struct multi_repo_node, node);

		if (pid < data->pid)
			node = node->rb_left;
		else
			if (pid > data->pid)
				node = node->rb_right;
			else
				if (pid == data->pid) {
					return data;
				} else
					return NULL;
	}
	return NULL;
}

struct multi_repo_node * multi_pid_search(pid_t pid)
{
	return __multi_pid_search(&multi_repo_tree, pid);
}

static struct multi_repo_node * single_init_tree(pid_t pid)
{
	struct multi_repo_node *multi_node = NULL;
	multi_node = kmalloc(sizeof(*multi_node), GFP_KERNEL);
	if(!multi_node)
		return NULL;

	multi_node->tree = RB_ROOT;
	multi_node->pid = pid;
/*#ifdef REPO_DEBUG*/
	{
	char pid_filename[7];
	snprintf(pid_filename, 6, "%d", pid);
	/*
	 * the file will iterate through the multi_repo_node structure
	 * */
	debugfs_create_file(pid_filename, S_IRUSR, repo, multi_node,
			&repo_monitor_fops);
	}
/*#endif*/
	return multi_node;
}

static int __multi_repo_create(struct rb_root *root, pid_t pid)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct multi_repo_node *tree = NULL;

	while (*new) {
		struct multi_repo_node *this = container_of(*new, struct multi_repo_node, node);

		parent = *new;
		if (pid < this->pid) {
			new = &((*new)->rb_left);
		} else
			if (pid > this->pid) {
				new = &((*new)->rb_right);
			} else {
				return -1;
			}
	}
	tree = single_init_tree(pid);

	if (!tree)
		return -1;

	rb_link_node(&tree->node, parent, new);
	rb_insert_color(&tree->node, root);
	return 0;
}

int multi_repo_create(pid_t pid)
{
	return __multi_repo_create(&multi_repo_tree, pid);
}

static int __multi_repo_delete(struct rb_root *root, pid_t pid)
{
	struct multi_repo_node *data = __multi_pid_search(root, pid);

	if (data) {
		clear_all_info(&data->tree);
		rb_erase(&data->node, root);
		kfree(data);
		return 0;
	}

	return -1;
}

int multi_repo_delete(pid_t pid)
{
	return __multi_repo_delete(&multi_repo_tree, pid);
}

void init_multi_repo(void)
{
/*#ifdef REPO_DEBUG*/
	repo = repo_debug_monitor("repositories");
/*#endif*/
	multi_repo_tree = RB_ROOT;
}

void exit_multi_repo(void)
{
}
