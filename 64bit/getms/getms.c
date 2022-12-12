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
             "Env   Segment start = 0x%012lx    end = 0x%012lx\n"
             "Arg   Segment start = 0x%012lx    end = 0x%012lx\n"	
             "Stack Segment start = 0x%012lx                 \n"
             "Heap  Segment start = 0x%012lx    end = 0x%012lx\n"	
             "Data  Segment start = 0x%012lx    end = 0x%012lx\n"
             "Text  Segment start = 0x%012lx    end = 0x%012lx\n",
             (unsigned long)mm->arg_start,   (unsigned long)mm->arg_end,
             (unsigned long)mm->env_start,   (unsigned long)mm->env_end,
             (unsigned long)mm->start_stack,
             (unsigned long)mm->start_brk,   (unsigned long)mm->brk,
             (unsigned long)mm->start_data,  (unsigned long)mm->end_data,
             (unsigned long)mm->start_code,  (unsigned long)mm->end_code
      );



    printk(	"\n-------------vm_area_struct -------------------\n");
    vm_temp = task->mm->mmap;
    if(vm_temp == NULL) {
        printk("%s: get vm_area failed\n", __func__);
        return -1;
    }
    while(vm_temp) {
        printk(  "start:0x%012lx    end:0x%012lx\n",
                 (unsigned long)vm_temp->vm_start,   (unsigned long)vm_temp->vm_end);
        vm_temp = vm_temp->vm_next;
    }

    return 0;
}