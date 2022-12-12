#include <linux/kernel.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#define ARRAY_SIZE 16
#define MALLOC_SIZE 32
#define THREAD_NUM 3

#define __NR_gettid 186
#define __NR_hubert 449
#define __NR_getms 450
#define __NR_get_phy_addr 451
#define __NR_cp_user_vaddr 452

typedef struct thread_data_package{
    int id;
    char* malloc_ptr;
}td_pack;

extern char **environ;

char global_array[ARRAY_SIZE];
char global_var;
char global_var_with_init=150;

void *thread_func(void*);

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;


long hubert_syscall(void)
{
	return syscall(__NR_hubert);
}

long getms_syscall(int pid)
{
        return syscall(__NR_getms, pid);
}

long get_phy_addr_syscall(int pid, unsigned long* vaddr, unsigned long* paddr, unsigned int addr_num)
{
        return syscall(__NR_get_phy_addr, pid, vaddr, paddr, addr_num);
}

long cp_user_vaddr_syscall( int pid, unsigned long* vaddr, unsigned int vaddr_num)
{
        return syscall(__NR_cp_user_vaddr, pid, vaddr, vaddr_num);
}

void print_memory_address(unsigned long vaddr[20], unsigned long paddr[20]){

    int i = 0;
    (void)printf("High address                                                 \n");
    (void)printf("--------------------------(args and env)---------------------\n");
    (void)printf("environ[0] at        : 0x%012lx ----> physical address = 0x%012lx\n", 
                 vaddr[i], paddr[i]);
    i++;
    (void)printf("-----------------------------Stack---------------------------\n");
    (void)printf("main_var             : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;
    (void)printf("main_array           : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;
    (void)printf("main_var_with_init   : 0x%012lx ----> physical address = 0x%012lx\n", 
               vaddr[i], paddr[i]);
    i++;

    (void)printf("-----------------------------Lib-----------------------------\n");
    (void)printf("printf library func  : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;
    (void)printf("malloc library func  : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;

    (void)printf("-----------------------------HEAP----------------------------\n");
    (void)printf("main_malloc_end      : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;
    (void)printf("main_malloc_start    : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;

    (void)printf("-----------------------------BSS-----------------------------\n");
    (void)printf("global_array         : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;
    (void)printf("global_var           : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;

    (void)printf("-----------------------------Data----------------------------\n");
    (void)printf("global_var_with_init : 0x%012lx ----> physical address = 0x%012lx\n", 
               vaddr[i], paddr[i]);
    i++;

    (void)printf("-----------------------------Text----------------------------\n");
    (void)printf("user_func            : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;
    (void)printf("main_func            : 0x%012lx ----> physical address = 0x%012lx\n", 
                vaddr[i], paddr[i]);
    i++;

}

int main(int argc, char* argv[]){
    long activity;
    activity = hubert_syscall();
    printf("%ld\n", activity);
    if(activity < 0)
    {
	perror("Sorry, Hubert. Your system call appers to have failed\n");
    }
    else
    {
	printf("Congratulations, Hubert! Your system call is functional. Run the command dmesg in the terminal and find out! \n");
    }
    char main_var;
    char main_var_with_init = 10;
    char main_array[ARRAY_SIZE];
    char *main_ptr;
    pid_t process_id;
    process_id = fork();
    if (process_id == 0) {
        sleep(1);
        printf("Child process!\n");
        int pid =  syscall(__NR_gettid);
        (void)printf("main tid: %ld\n", syscall(__NR_gettid));
        main_ptr = (char *)malloc(MALLOC_SIZE);
        
        main_var_with_init = 120;
        for (int i=0; i < ARRAY_SIZE; i++){
            main_array[i] = i;
        }
        (void)printf("main_var           = %d\n",(int)main_var);
        (void)printf("main_var_with_init = %d\n",(int)main_var_with_init);
        
        unsigned long user_vaddr[20]={0};
        unsigned long user_paddr[20]={0};
        unsigned int addr_num = 0;
        user_vaddr[addr_num++] = (unsigned long)environ;
        user_vaddr[addr_num++] = (unsigned long)&main_var;
        user_vaddr[addr_num++] = (unsigned long)main_array;
        user_vaddr[addr_num++] = (unsigned long)&main_var_with_init;
        user_vaddr[addr_num++] = (unsigned long)&printf;
        user_vaddr[addr_num++] = (unsigned long)&malloc;
        user_vaddr[addr_num++] = (unsigned long)main_ptr+MALLOC_SIZE;
        user_vaddr[addr_num++] = (unsigned long)main_ptr;
        user_vaddr[addr_num++] = (unsigned long)global_array;
        user_vaddr[addr_num++] = (unsigned long)&global_var;
        user_vaddr[addr_num++] = (unsigned long)&global_var_with_init;
        user_vaddr[addr_num++] = (unsigned long)&print_memory_address;
        user_vaddr[addr_num++] = (unsigned long)&main;
        
        get_phy_addr_syscall(pid, user_vaddr, user_paddr, addr_num);
        
        activity = getms_syscall(pid);
        printf("%ld\n", activity);
        if(activity < 0)
        {
            perror("Sorry, Hubert. Your system call appers to have failed\n");
        }
        else
        {
            printf("Congratulations, Hubert! Your system call is functional. Run the command dmesg in the terminal and find out! \n");
        }
        
        print_memory_address(user_vaddr, user_paddr);
        
        free(main_ptr);
    }
    
    if (process_id > 0) {
        printf("Parent process!\n");
        int pid =  syscall(__NR_gettid);
        long activity;
        (void)printf("main tid: %ld\n", syscall(__NR_gettid));
        main_ptr = (char *)malloc(MALLOC_SIZE);

        main_var_with_init = 120;
        for (int i=0; i < ARRAY_SIZE; i++){
            main_array[i] = i;
        }
        (void)printf("main_var           = %d\n",(int)main_var);
        (void)printf("main_var_with_init = %d\n",(int)main_var_with_init);

        unsigned long user_vaddr[20]={0};
        unsigned long user_paddr[20]={0};
        unsigned int addr_num = 0;
        user_vaddr[addr_num++] = (unsigned long)environ;
        user_vaddr[addr_num++] = (unsigned long)&main_var;
        user_vaddr[addr_num++] = (unsigned long)main_array;
        user_vaddr[addr_num++] = (unsigned long)&main_var_with_init;
        user_vaddr[addr_num++] = (unsigned long)&printf;
        user_vaddr[addr_num++] = (unsigned long)&malloc;
        user_vaddr[addr_num++] = (unsigned long)main_ptr+MALLOC_SIZE;
        user_vaddr[addr_num++] = (unsigned long)main_ptr;
        user_vaddr[addr_num++] = (unsigned long)global_array;
        user_vaddr[addr_num++] = (unsigned long)&global_var;
        user_vaddr[addr_num++] = (unsigned long)&global_var_with_init;
        user_vaddr[addr_num++] = (unsigned long)&print_memory_address;
        user_vaddr[addr_num++] = (unsigned long)&main;

        get_phy_addr_syscall(pid, user_vaddr, user_paddr, addr_num);

        activity = getms_syscall(pid);
        printf("%ld\n", activity);
        if(activity < 0)
        {
            perror("Sorry, Hubert. Your system call appers to have failed\n");
        }
        else
        {
            printf("Congratulations, Hubert! Your system call is functional. Run the command dmesg in the terminal and find out! \n");
        }

        print_memory_address(user_vaddr, user_paddr);

        free(main_ptr);
    }
    //fgetc(stdin);
    return EXIT_SUCCESS;
}