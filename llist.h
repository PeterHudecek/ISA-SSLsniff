
/* Předmět: Algoritmy (IAL) - FIT VUT v Brně
 * Hlavičkový soubor pro c206.c (Dvousměrně vázaný lineární seznam)
 * Vytvořil: Martin Tuček, září 2005
 * Upravil: Kamil Jeřábek, září 2018
 *  
 * Tento soubor, prosíme, neupravujte!  
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>

#define FALSE 0
#define TRUE 1

extern int errflg;
extern int solved;
 
typedef struct LLElem {                 	/* prvek dvousměrně vázaného seznamu */ 
        struct LLElem *lptr;          		/* ukazatel na předchozí prvek seznamu */
        struct LLElem *rptr;        		/* ukazatel na následující prvek seznamu */
		struct sockaddr_in source,dest; 	/* ipv4 client a server ip */
		struct sockaddr_in6 source6, dest6; /* ipv6 klient a server ip */
		int ipvers;							/*flag na ip verziu */
		__u16   cPort; 						/* client port number */
		__u16   sPort; 						/* server port number */
		short int SNI;						/* Server name indication */
		unsigned long bytes;				/* pocet bytov */
		long secs;							/* pcoet sekund */
		long usecs;							/*pocet mikrosekund */
		
} *LLElemPtr;

typedef struct {                                  /* dvousměrně vázaný seznam */
    LLElemPtr First;                      /* ukazatel na první prvek seznamu */
    LLElemPtr Act;                     /* ukazatel na aktuální prvek seznamu */
    LLElemPtr Last;                    /* ukazatel na posledni prvek seznamu */
} LList;

                                             /* prototypy jednotlivých funkcí */
void LInitList (LList *L);
void LDisposeList (LList *);
void LInsertFirst (LList *);
void LInsertLast(LList *L,LLElemPtr Elem);
void LFirst (LList *);
void LLast (LList *);
void LCopyFirst (LList *);
void LCopyLast (LList *);
void LDeleteFirst (LList *);
void LDeleteLast (LList *);
void LPostDelete (LList *);
void LPreDelete (LList *);
void LPostInsert (LList *, int);
void LPreInsert (LList *, int);
void LCopy (LList *);
void LActualize (LList *);
void LSucc (LList *);
void LPred (LList *);
int LActive (LList *);

LLElemPtr FindComm(LList *L,LLElemPtr Elem);
void DeleteElement(LList *L, LLElemPtr Elem);

/* Konec hlavičkového souboru c206.h */
