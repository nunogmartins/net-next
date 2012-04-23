#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <asm/uaccess.h>

#include "inject_monitor.h"
#include "debugfs_monitor.h"

static ssize_t inject_manager_write(struct file *file, const char __user *user_buf,
		size_t size, loff_t *ppos);

static struct dentry *inject_dir;

static int inject_show(struct seq_file *seq, void *v)
{
	return 0;
}

static int inject_open(struct inode *inode, struct file *file)
{
	return single_open(file, inject_show, inode->i_private);
}

static const struct file_operations inject_manager = {
	.owner = THIS_MODULE,
	/*.open = inject_open,*/
	.write = inject_manager_write,
	/*.release = single_release,*/
};

/*
 * seen from pktgen.c file
 * */
static int strn_len(const char __user * user_buff, unsigned int maxlen)
{
	int i;

	for (i = 0; i < maxlen; i++) {
		char c;
		if (get_user(c, &user_buff[i]))
			return -EFAULT;
		switch (c) {
			case '\"':
			case '\n':
			case '\r':
			case '\t':
			case ' ':
				goto done_str;
				break;
			default:
				break;
		}
	}
done_str:
	return i;
}

static ssize_t inject_manager_write(struct file *file, const char __user *user_buf,
		size_t size, loff_t *ppos)
{
	/*
	 * commands sent from file
	 * */
	char name[128];
	char prefix[10];
	int ret;
	int i;

	pr_info("how much data %zu and size of name %zu what was submited:%s\n", size, sizeof(name), user_buf);

	if (size > sizeof(name))
		return size;

	i = strn_len(user_buf, 10);
	memset(prefix, 0 , 10);
	copy_from_user(prefix, user_buf, i);

	if (!strcmp(prefix, "pkt")) {
		pr_info("pkt prefix was found ...\n");

	} else if (!strcmp(prefix, "pid")) {
		int start = i, stop;
		stop = strn_len(&user_buf[start], 10);
		pr_info("pid prefix was found len %d and pid is %s...\n", stop, &user_buf[start]);
	} else
		pr_info("Sent from user:%s\n", user_buf);



	return size;
}

int dummy;

void init_inject_monitor(void)
{
	inject_dir = inject_debug_monitor("inject");
	debugfs_create_file("inject_manager", S_IWUSR, inject_dir, &dummy, &inject_manager);
}

void exit_inject_monitor(void)
{
}
