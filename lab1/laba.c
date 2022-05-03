#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

static int major;
static struct class* cls;
static size_t list_size = 20;
static size_t cur_list_size = 0;
static size_t* inputs_len_list;
static struct proc_dir_entry *proc_file;
static struct proc_dir_entry *offset_proc_file;
static long list_offset = -1;

static int device_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "open\n");
    return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "release\n");
    return 0;
}

static ssize_t device_read(struct file *filp, char __user *buffer,
                           size_t length, loff_t *offset)
{
    printk(KERN_INFO "input lengths history:\n");
    for (size_t i = 0; i < cur_list_size; i++){
        printk(KERN_INFO "%zu\n", inputs_len_list[i]);
    }
    return 0;
}

static ssize_t device_write(struct file *filp, const char __user *buff,
                            size_t length, loff_t *off)
{
    printk(KERN_INFO "write: %zu\n", length);

    if (cur_list_size == list_size){
        size_t* tmp = kmalloc((list_size + 20) * sizeof(size_t), GFP_KERNEL);
        for (size_t i = 0; i < list_size; i++){
            tmp[i] = inputs_len_list[i];
        }
        kfree(inputs_len_list);
        inputs_len_list = tmp;
        list_size += 20;
    }
    inputs_len_list[cur_list_size] = length;
    cur_list_size++;
    return length;
}

static const struct file_operations chardev_fops = {
        .read = device_read,
        .write = device_write,
        .open = device_open,
        .release = device_release,
};

static ssize_t procfile_read(struct file *file, char __user *buffer,
                             size_t buffer_length, loff_t *offset)
{
    printk(KERN_INFO "read from proc\n");

    if (*offset == 0){
        char* str_buffer = kmalloc(cur_list_size * 22 * sizeof(char), GFP_KERNEL);
        size_t res_len = 0;
        size_t iter = 0;
        while (res_len + 22 <= buffer_length && iter < cur_list_size){
            res_len += sprintf(str_buffer + res_len, "%zu\n", inputs_len_list[iter]);
            iter++;
        }
        if (copy_to_user(buffer, str_buffer, res_len)){
            printk(KERN_ERR "error in proc\n");
            kfree(str_buffer);
            return 0;
        }
        kfree(str_buffer);
        *offset = res_len;
        return res_len;
    }
    else return 0;
}

static const struct proc_ops proc_file_fops = {
        .proc_read = procfile_read,
};

static ssize_t offset_procfile_write(struct file *file, const char __user *buff,
        size_t len, loff_t *off) {
    int res = kstrtol_from_user(buff, len, 10, &list_offset);
    if (res < 0) list_offset = -1;
    printk(KERN_INFO "%ld\n", list_offset);
    return len;
}

static ssize_t offset_procfile_read(struct file *file, char __user *buffer,
        size_t buffer_length, loff_t *offset) {
    printk(KERN_INFO "read from offset_proc\n");

    if (*offset == 0){
        char* str_buffer = kmalloc(30 * sizeof(char), GFP_KERNEL);
        size_t res_len = 0;
        if (buffer_length >= 30 * sizeof(char)) {
            if (list_offset < 0) res_len = sprintf(str_buffer, "invalid offset\n");
            else if (list_offset >= cur_list_size) res_len =
                    sprintf(str_buffer, "offset is out of array\n");
            else res_len = sprintf(str_buffer, "%zu\n", inputs_len_list[cur_list_size - 1 - list_offset]);
    }
    if (copy_to_user(buffer, str_buffer, res_len)){
        printk(KERN_ERR "error in offset proc\n");
        kfree(str_buffer);
        return 0;
    }
    kfree(str_buffer);
    *offset = res_len;
    return res_len;
    }
    else return 0;
}

static const struct proc_ops offset_proc_file_fops = {
        .proc_write = offset_procfile_write,
        .proc_read = offset_procfile_read
};

static int __init my_module_init(void) {
    printk(KERN_INFO "init\n");

    major = register_chrdev(0, "var1", &chardev_fops);

    if (major < 0) {
        printk(KERN_ERR "registering char device failed with %d\n", major);
        return major;
    }

    printk(KERN_INFO "char device created with major %d\n", major);
    cls = class_create(THIS_MODULE, "var1");

    if (IS_ERR(cls)){
        unregister_chrdev(major, "var1");
        printk(KERN_ERR "could not create class\n");
        return PTR_ERR(cls);
    }

    struct device* device = device_create(cls, NULL, MKDEV(major, 0), NULL, "var1");

    if (IS_ERR(device)){
        class_destroy(cls);
        unregister_chrdev(major, "var1");
        printk(KERN_ERR "could not create device\n");
        return PTR_ERR(device);
    }

    proc_file = proc_create("var1", 0444, NULL, &proc_file_fops);

    if (proc_file == NULL){
        device_destroy(cls, MKDEV(major, 0));
        class_destroy(cls);
        unregister_chrdev(major, "var1");
        printk(KERN_ERR "could not initialize proc file\n");
        return -1;
    }

    offset_proc_file = proc_create("var1_offset", 0444, NULL, &offset_proc_file_fops);

    if (offset_proc_file == NULL){
        device_destroy(cls, MKDEV(major, 0));
        class_destroy(cls);
        unregister_chrdev(major, "var1");
        proc_remove(proc_file);
        printk(KERN_ERR "could not initialize offset proc file\n");
        return -1;
    }

    inputs_len_list = kmalloc(list_size * sizeof(size_t), GFP_KERNEL);

    printk(KERN_INFO "driver init success\n");

    return 0;
}
static void __exit my_module_exit(void) {
    kfree(inputs_len_list);
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, "var1");
    proc_remove(proc_file);
    proc_remove(offset_proc_file);

    printk(KERN_INFO "driver died\n");
}

module_init(my_module_init);
module_exit(my_module_exit);