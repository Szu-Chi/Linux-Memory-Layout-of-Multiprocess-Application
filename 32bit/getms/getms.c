#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>

SYSCALL_DEFINE1(getms, int, pid){
    struct task_struct *task = NULL;
    struct vm_area_struct *vm_temp = NULL;
    struct mm_struct *mm = NULL;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task == NULL) {
        printk("%s: get pid task struct failed\n", __func__);
        return -1;
    }

    mm = task->mm;

    printk(  "\n-------------mm_struct result-------------------\n"
             "Env   Segment start = 0x%08x    end = 0x%08x\n"
             "Arg   Segment start = 0x%08x    end = 0x%08x\n"	
             "Stack Segment start = 0x%08x                 \n"
             "Heap  Segment start = 0x%08x    end = 0x%08x\n"	
             "Data  Segment start = 0x%08x    end = 0x%08x\n"
             "Text  Segment start = 0x%08x    end = 0x%08x\n",
             (unsigned int)mm->arg_start,   (unsigned int)mm->arg_end,
             (unsigned int)mm->env_start,   (unsigned int)mm->env_end,
             (unsigned int)mm->start_stack,
             (unsigned int)mm->start_brk,   (unsigned int)mm->brk,
             (unsigned int)mm->start_data,  (unsigned int)mm->end_data,
             (unsigned int)mm->start_code,  (unsigned int)mm->end_code
      );



    printk(	"\n-------------vm_area_struct -------------------\n");
    vm_temp = task->mm->mmap;
    if(vm_temp == NULL) {
        printk("%s: get vm_area failed\n", __func__);
        return -1;
    }
    while(vm_temp) {
        printk(  "start:0x%08x    end:0x%08x\n",
                 (unsigned int)vm_temp->vm_start,   (unsigned int)vm_temp->vm_end);
        vm_temp = vm_temp->vm_next;
    }

    return 0;
}