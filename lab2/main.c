#include <linux/module.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/string.h>
#include <linux/moduleparam.h>

#define MY_SECTOR_SIZE 512

int c = 0; //Variable for Major Number

static int disk_size = 30;
module_param(disk_size, int, 0);

/* Structure associated with Block device*/
struct mydiskdrive_dev
{
    int size;
    u8 *data;
    spinlock_t lock;
    struct request_queue *queue;
    struct gendisk *gd;

}device;

struct mydiskdrive_dev *x;

static int my_open(struct block_device *x, fmode_t mode)
{
    int ret=0;
    printk(KERN_INFO "mydiskdrive : open \n");

    return ret;

}

static void my_release(struct gendisk *disk, fmode_t mode)
{
    printk(KERN_INFO "mydiskdrive : closed \n");
}

static struct block_device_operations fops =
        {
                .owner = THIS_MODULE,
                .open = my_open,
                .release = my_release,
        };

int mydisk_init(void)
{
    (device.data) = vmalloc(disk_size * 1024 * 1024);
    if (device.data == NULL) return -1;

    return disk_size;
}

static int rb_transfer(struct request *req)
{
    int dir = rq_data_dir(req);
    int ret = 0;
    /*starting sector
     *where to do operation*/
    sector_t start_sector = blk_rq_pos(req);
    unsigned int sector_cnt = blk_rq_sectors(req); /* no of sector on which opn to be done*/
    struct bio_vec bv;
#define BV_PAGE(bv) ((bv).bv_page)
#define BV_OFFSET(bv) ((bv).bv_offset)
#define BV_LEN(bv) ((bv).bv_len)
    struct req_iterator iter;
    sector_t sector_offset;
    unsigned int sectors;
    u8 *buffer;
    sector_offset = 0;
    rq_for_each_segment(bv, req, iter)
    {
        buffer = page_address(BV_PAGE(bv)) + BV_OFFSET(bv);
        if (BV_LEN(bv) % (MY_SECTOR_SIZE) != 0)
        {
            printk(KERN_ERR"bio size is not a multiple of sector size\n");
            ret = -EIO;
        }
        sectors = BV_LEN(bv) / MY_SECTOR_SIZE;
        printk(KERN_DEBUG "my disk: Start Sector: %llu, Sector Offset: %llu; "
                          "Buffer: %p; Length: %u sectors\n",
                (unsigned long long)(start_sector),
                (unsigned long long)(sector_offset),
                buffer, sectors);

        if (dir == WRITE) /* Write to the device */
        {
            memcpy((device.data)+((start_sector+sector_offset)*MY_SECTOR_SIZE)
                    ,buffer,sectors*MY_SECTOR_SIZE);
        }
        else /* Read from the device */
        {
            memcpy(buffer,(device.data)+((start_sector+sector_offset)*MY_SECTOR_SIZE),
                   sectors*MY_SECTOR_SIZE);
        }
        sector_offset += sectors;
    }

    if (sector_offset != sector_cnt)
    {
        printk(KERN_ERR "mydisk: bio info doesn't match with the request info");
        ret = -EIO;
    }
    return ret;
}
/** request handling function**/
static void dev_request(struct request_queue *q)
{
    struct request *req;
    int error;
    while ((req = blk_fetch_request(q)) != NULL) /*check active request
						      *for data transfer*/
    {
        error=rb_transfer(req);// transfer the request for operation
        __blk_end_request_all(req, error); // end the request
    }
}

int device_setup(void)
{
    if (mydisk_init() < 0) {
        printk(KERN_ERR "error during memory init\n");
        return -1;
    }
    c = register_blkdev(c, "mydisk");// major no. allocation
    if (c < 0) {
        printk(KERN_ERR "error during major allocation\n");
        goto err_major;
    }
    printk(KERN_ALERT "Major Number is : %d",c);
    spin_lock_init(&device.lock); // lock for queue
    device.queue = blk_init_queue( dev_request, &device.lock);

    if (device.queue == NULL) {
        printk(KERN_ERR "error during queue preparation\n");
        goto err_queue;
    }

    device.gd = alloc_disk(8); // gendisk allocation

    if (device.gd == NULL) {
        printk(KERN_ERR "error during gendisk allocation\n");
        goto err_gendisk;
    }

    (device.gd)->major=c; // major no to gendisk
    device.gd->first_minor=0; // first minor of gendisk

    device.gd->fops = &fops;
    device.gd->private_data = &device;
    device.gd->queue = device.queue;
    device.size = disk_size * 2048;
    printk(KERN_INFO"THIS IS DEVICE SIZE %d",device.size);
    sprintf(((device.gd)->disk_name), "mydisk");
    set_capacity(device.gd, device.size);
    add_disk(device.gd);
    return 0;

err_gendisk:
    blk_cleanup_queue(device.queue);
err_queue:
    unregister_blkdev(c, "mydisk");
err_major:
    vfree(device.data);
    return -1;
}

static int __init mydiskdrive_init(void)
{
    if (disk_size < 20 || disk_size > 90) {
        printk(KERN_ERR "invalid size\n");
        return -EINVAL;
    }
    return device_setup();
}

void mydisk_cleanup(void)
{
    vfree(device.data);
}

void __exit mydiskdrive_exit(void)
{
    del_gendisk(device.gd);
    put_disk(device.gd);
    blk_cleanup_queue(device.queue);
    unregister_blkdev(c, "mydisk");
    mydisk_cleanup();
}

module_init(mydiskdrive_init);
module_exit(mydiskdrive_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Author");
MODULE_DESCRIPTION("BLOCK DRIVER");