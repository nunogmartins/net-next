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
 * multi_pid_repository.h
 *
 *  Created on: Apr 23, 2012
 *      Author: nuno
 */

#ifndef MULTI_PID_REPOSITORY_H_
#define MULTI_PID_REPOSITORY_H_

#include <linux/rbtree.h>
#include <linux/types.h>

struct multi_repo_node {
	struct rb_node node;
	struct rb_root tree;
	pid_t pid;
};

struct multi_repo_node * multi_pid_search(pid_t pid);
int multi_repo_create(pid_t pid);
int multi_repo_delete(pid_t pid);

void init_multi_repo(void);
void exit_multi_repo(void);

#endif /* MULTI_PID_REPOSITORY_H_ */
