/* macros de syscalls */

extern int errno;

#define my__syscall_return(type, res) \
do { \
    if ((unsigned long)(res) >= (unsigned long)(-(128 + 1))) { \
        errno = -(res); \
        res = -1; \
    } \
    return (type) (res); \
} while (0)

/* XXX - _foo needs to be __foo, while __NR_bar could be _NR_bar. */
#define my_syscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
    : "=a" (__res) \
    : "0" (__NR_##name)); \
my__syscall_return(type,__res); \
}

#define my_syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("push %%ebx ; movl %2,%%ebx ; int $0x80 ; pop %%ebx" \
    : "=a" (__res) \
    : "0" (__NR_##name),"ri" ((long)(arg1)) : "memory"); \
my__syscall_return(type,__res); \
}

#define my_syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("push %%ebx ; movl %2,%%ebx ; int $0x80 ; pop %%ebx" \
    : "=a" (__res) \
    : "0" (__NR_##name),"ri" ((long)(arg1)),"c" ((long)(arg2)) \
    : "memory"); \
my__syscall_return(type,__res); \
}

#define my_syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("push %%ebx ; movl %2,%%ebx ; int $0x80 ; pop %%ebx" \
    : "=a" (__res) \
    : "0" (__NR_##name),"ri" ((long)(arg1)),"c" ((long)(arg2)), \
          "d" ((long)(arg3)) : "memory"); \
my__syscall_return(type,__res); \
}

#define my_syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4) \
type name (type1 arg1, type2 arg2, type3 arg3, type4 arg4) \
{ \
long __res; \
__asm__ volatile ("push %%ebx ; movl %2,%%ebx ; int $0x80 ; pop %%ebx" \
    : "=a" (__res) \
    : "0" (__NR_##name),"ri" ((long)(arg1)),"c" ((long)(arg2)), \
      "d" ((long)(arg3)),"S" ((long)(arg4)) : "memory"); \
my__syscall_return(type,__res); \
}

#define my_syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4, \
      type5,arg5) \
type name (type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{ \
long __res; \
__asm__ volatile ("push %%ebx ; movl %2,%%ebx ; movl %1,%%eax ; " \
                  "int $0x80 ; pop %%ebx" \
    : "=a" (__res) \
    : "i" (__NR_##name),"ri" ((long)(arg1)),"c" ((long)(arg2)), \
      "d" ((long)(arg3)),"S" ((long)(arg4)),"D" ((long)(arg5)) \
    : "memory"); \
my__syscall_return(type,__res); \
}

