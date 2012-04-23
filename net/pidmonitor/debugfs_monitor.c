/*
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

#include <linux/debugfs.h>

struct dentry *root_pidmonitor_dir;

static int monitor_debugfs_directory(const char *dir_name)
{
	root_pidmonitor_dir = debugfs_create_dir(dir_name, NULL);
	return 0;
}

struct dentry *repo_debug_monitor(const char *dirname)
{
	return debugfs_create_dir(dirname, root_pidmonitor_dir);
}

struct dentry *inject_debug_monitor(const char *dirname)
{
	return debugfs_create_dir(dirname, root_pidmonitor_dir);
}

struct dentry *syscalls_debug_monitor(const char *dirname)
{
	return debugfs_create_dir(dirname, root_pidmonitor_dir);
}
/*
struct dentry *memory_debug_monitor(const char *dirname)
{
	return debugfs_create_dir(dirname, root_pidmonitor_dir);
}
*/
struct dentry *filter_debug_monitor(const char *dirname)
{
	return debugfs_create_dir(dirname, root_pidmonitor_dir);
}


int init_debugfs_monitor(void)
{
	monitor_debugfs_directory("pidmonitor");
	return 0;
}

void exit_debugfs_monitor(void)
{
	debugfs_remove_recursive(root_pidmonitor_dir);
}
