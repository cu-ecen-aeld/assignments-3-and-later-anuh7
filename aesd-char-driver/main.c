/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> 
#include "linux/slab.h"
#include "linux/string.h"
#include <linux/uaccess.h>

#include "aesdchar.h"
#include "aesd_ioctl.h"


int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Anuhya Kuraparthy"); 
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    PDEBUG("open");
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    filp->private_data = NULL;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev;
    struct aesd_buffer_entry *tmp_buf;
    int tmp_buf_count = 0;
    size_t offset_bytes;
    dev = filp->private_data;
    
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    
    mutex_lock(&aesd_device.lock);
    tmp_buf = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &offset_bytes);
    
    if( tmp_buf == NULL )
    {
       // *f_pos = 0;
        goto handle_error;
    }
    
    if( (tmp_buf->size - offset_bytes) < count )
    {
        *f_pos += tmp_buf->size - offset_bytes;
        tmp_buf_count = tmp_buf->size - offset_bytes;
    }
    else
    {
        *f_pos += count;
        tmp_buf_count = count;
    }
    
    if( copy_to_user(buf, tmp_buf->buffptr+offset_bytes, tmp_buf_count))
    {
        retval = -EFAULT;
        goto handle_error;
    }
    
    retval = tmp_buf_count;

    handle_error : mutex_unlock(&aesd_device.lock);
    

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    char *tmp_buf;		
    bool packet_flag = false;	
    struct aesd_dev *dev;	
    int packet_len = 0;	
    struct aesd_buffer_entry write_entry;	
    char *ret;			
    int i;
    ssize_t retval = 0;
    int extra;			
    
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    
    dev = filp->private_data;
    mutex_lock(&aesd_device.lock);
    
    tmp_buf = (char *)kmalloc(count, GFP_KERNEL);
    if( tmp_buf == NULL )
    {
        retval = -ENOMEM;
        goto end;
    }
    
    if(copy_from_user(tmp_buf, buf, count))
    {
        retval = -EFAULT;
        goto free_memory;
    }
    
    for(i=0; i< count; i++)
    {
        if(tmp_buf[i] == '\n')
        {
            packet_flag = true;
            packet_len = i+1;
            break;
        }
    }
    
    if( dev->buff_size == 0 )		
    {
        dev->buff_ptr = (char *)kmalloc(count, GFP_KERNEL);	
        if( dev->buff_ptr == NULL )
        {
            retval = -ENOMEM;
            goto free_memory;
        }
        memcpy(dev->buff_ptr, tmp_buf, count);
        dev->buff_size += count;
    }
    else
    {
       
        if(packet_flag)
        {
            extra = packet_len;
        }
        else
        {
            extra = count;
        }
        dev->buff_ptr = (char *)krealloc(dev->buff_ptr, dev->buff_size + extra , GFP_KERNEL);
        if( dev->buff_ptr == NULL )
        {
            retval = -ENOMEM;
            goto free_memory;
        }
        memcpy(dev->buff_ptr + dev->buff_size, tmp_buf, extra);	
        dev->buff_size += extra;
    }
    
    if(packet_flag)
    {
        write_entry.buffptr = dev->buff_ptr;
        write_entry.size = dev->buff_size;
        ret = aesd_circular_buffer_add_entry(&dev->buffer, &write_entry);
        
        if( ret != NULL )
        {
            kfree(ret);
        }
        dev->buff_size = 0;
    }
    
    retval = count;
    free_memory : kfree(tmp_buf);
    end : mutex_unlock(&aesd_device.lock);
    return retval;
}


static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
	long return_value = 0;
	int commands = 0;
	int i;
	loff_t offset = 0;
	struct aesd_dev *dev=filp->private_data;
  	struct aesd_buffer_entry *tmp_buf = NULL;
	
	PDEBUG("aesd_adjust_file_offset");
	
	mutex_lock(&aesd_device.lock);
	
	AESD_CIRCULAR_BUFFER_FOREACH(tmp_buf, &dev->buffer, commands)
	{
      		//free(tmp_buffer->buffptr);
 	}

	if (write_cmd > commands || 
		write_cmd > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED ||
		write_cmd_offset >= (dev->buffer.entry[write_cmd].size))
		{
			return_value = -EINVAL;
		}
	else
	{
		for (i=0; i<write_cmd; i++)
			offset += dev->buffer.entry[i].size;
		
		offset = offset + write_cmd_offset;
		filp->f_pos = offset;
	}
	
	mutex_unlock(&aesd_device.lock);
	
	return return_value;	
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long return_value = 0;
	struct aesd_seekto seekto;
	
	PDEBUG("aesd_ioctl");
	
	if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

	switch(cmd)
	{
		case AESDCHAR_IOCSEEKTO:
			{
				if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
					return_value = -EFAULT;
				else
					return_value = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
				break;
			}
		default:
			return_value = -EINVAL;		//? enotty
			break;
	}
	
	return return_value;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    loff_t return_value;
    struct aesd_dev *dev = filp->private_data;
    loff_t size = 0;
    struct aesd_buffer_entry *entry = NULL;
    int index = 0;
    
    //size = dev->buffer.buffer_size;				///////
    mutex_lock(&aesd_device.lock);
    
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &dev->buffer, index)
		size += entry->size;

    
    return_value = fixed_size_llseek(filp, offset, whence, size);
    mutex_unlock(&aesd_device.lock);

    return return_value;
}



struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek = 	aesd_llseek,
    .unlocked_ioctl = aesd_ioctl
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) 
    {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    
    aesd_circular_buffer_init(&aesd_device.buffer);
    
    result = aesd_setup_cdev(&aesd_device);

    if(result)
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    int index;
    struct aesd_buffer_entry *ptr;
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    cdev_del(&aesd_device.cdev);
    
    AESD_CIRCULAR_BUFFER_FOREACH(ptr, &aesd_device.buffer, index)
    {
    	if (ptr->buffptr != NULL)
    	{
    		kfree(ptr->buffptr);
    		ptr->size = 0;
    	}
        
    }
    mutex_destroy(&aesd_device.lock);
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
