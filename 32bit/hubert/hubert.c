#include <linux/kernel.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE0(hubert)

{
    printk("I am Hubert.\n");
    return 0;
}
