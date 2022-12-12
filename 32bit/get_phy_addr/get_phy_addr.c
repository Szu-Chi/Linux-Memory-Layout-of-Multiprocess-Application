#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/io.h>

SYSCALL_DEFINE4(get_phy_addr, int, pid, unsigned int*, vaddr, unsigned int*, paddr, unsigned int, addr_num){
    unsigned int *pData, *wData;
    pData = kmalloc(sizeof(unsigned int)*addr_num, GFP_KERNEL);
    wData = kmalloc(sizeof(unsigned int)*addr_num, GFP_KERNEL);
    copy_from_user(pData, vaddr, sizeof(unsigned int)*addr_num);
    int i;
    for(i=0; i<addr_num; i++){
        printk("virtual address = 0x%08x", (unsigned int)pData[i]);
    }
    

    struct task_struct *task = NULL;
    struct vm_area_struct *vm_temp = NULL;
    struct mm_struct *mm = NULL;

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if(task == NULL) {
        printk("%s: get pid task struct failed\n", __func__);
        return -1;
    }
    mm = task->mm;


    for(i=0; i<addr_num; i++){
        printk("virtual address = 0x%08x", (unsigned int)pData[i]);
        
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep,pte;

        struct page *page = NULL;
        unsigned int physical_address;
        unsigned int va = pData[i];

        pgd = pgd_offset(mm, va);
        if (pgd_none(*pgd) || pgd_bad(*pgd)){
            printk("Invalid pgd: virtual address = 0x%08x \n",(unsigned int)va);
            continue;
        }

        p4d = p4d_offset(pgd, va);
        if (p4d_none(*p4d) || p4d_bad(*p4d)){
            printk("Invalid p4d: virtual address = 0x%08x \n",(unsigned int)va);
            continue;
        }

        pud = pud_offset(p4d, va);
        if (pud_none(*pud) || pud_bad(*pud)){
            printk("Invalid pud: virtual address = 0x%08x \n",(unsigned int)va);
            continue;    
        }

        pmd = pmd_offset(pud, va);
        if (pmd_none(*pmd) || pmd_bad(*pmd)){
            printk("Invalid pmd: virtual address = 0x%08x \n",(unsigned int)va);
            continue;    
        }

        ptep = pte_offset_map(pmd, va);
        if (!ptep){
            continue;
        }
        pte = *ptep;

        page = pte_page(pte);
        if (page){
            wData[i] = page_to_phys(page);
        }
        pte_unmap(ptep);

    }


    for(i=0; i<addr_num; i++){
        printk(
                "virtual address = 0x%08x ----> physical address = 0x%08x\n",
                (unsigned int)pData[i],  (unsigned int)wData[i]
        );
    }
    copy_to_user(paddr, wData, sizeof(unsigned int)*addr_num);

    kfree(pData);
    kfree(wData);
    return 0;
}
