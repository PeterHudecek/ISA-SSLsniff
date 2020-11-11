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
#include "llist.h"

struct sockaddr_in source,dest;
struct sockaddr_in6 source6, dest6;
LList comms;
struct isaSettings
{			
	int interfaceSet;		//flag ci bolo urcene zariadenie
	char interface[30];		//nazov zariadenia
	int pcapfileset;		//flag ci bol urceny pcap subor
	pcap_t *handle;			//pointer na pcap spojenie
	/********************** TODO malloc na velkost nazvu ********************************************************************/

	char pcapfilename[30];	//nazov suboru
};

//Funkcia pre spracovanie argumentov zo vsstupu a uloženie ich do struktury
//Funkcia vracia strukturu s nastavenim packet snifferu
struct isaSettings setSettings(struct isaSettings s, int argc, char *argv[]);
//Callback funkcia pre pcap_loop(), funkcia spracuje zachyteny paket a vytlaci ho na stdout 
void process_transport_layer(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
//funkcia na spracovanie tsl headeru
void process_tls_header(const u_char *data, int dataSize, struct LLElem);

int main(int argc, char *argv[])
{	
	struct isaSettings s = setSettings(s, argc, argv); 
	LInitList(&comms);
	

	//cyklus pre zachytavanie packetov
	pcap_loop(s.handle,-1,process_transport_layer, NULL);
	/*
	LLElemPtr tempPtr = comms.First;
	if(comms.First != NULL) //overenie ci sa nema rusit prazdny zoznam
	{
		while(tempPtr->rptr != NULL) //cyklus na mazanie prvkov a uvolnenie alokovanej pamate
		{
			char time[30];	//premenna pre ulozenie hodnoty casu
			memset(time,0,sizeof(time));
			strftime(time,30,"%X.",localtime(&tempPtr->secs));		//konvertovanie
			printf("Time is: %s%ld \n",time,tempPtr->usecs); 					//vypis casu
			printf("Source IP/hostname: %s \n",inet_ntoa(tempPtr->source.sin_addr));
			printf("Client port is %u \n", ntohs(tempPtr->cPort));
			printf("Dest IP/hostname: %s \n",inet_ntoa(tempPtr->dest.sin_addr));
			tempPtr = tempPtr->rptr;
		}
	}
	*/
	LDisposeList(&comms);
	return 0;
}

struct isaSettings setSettings(struct isaSettings s, int argc, char *argv[]){
	//Zakladne nastavenie
	s.interfaceSet = 0;		
	s.pcapfileset = 0;

	pcap_if_t *interfaces, *iterator;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;		
	bpf_u_int32 net;
	struct bpf_program fp;
	

	int opt;			//iterator pre spracovanie argumentov


	//spracovanie argumentov 
	while((opt = getopt(argc,argv, "r:l:")) != -1){
		switch(opt){
			case 'l':
				if(optarg != NULL){
					s.interfaceSet = 1;
					strcpy(s.interface,optarg);
				}
				else{
					printf("-l vyzaduje argument s nazvom interfacu na ktorom ma bezat\n");
					exit(1);
				}
				
				break;
			case 'r':
				if(optarg != NULL){
					if(optarg != NULL){
					s.pcapfileset = 1;
					strcpy(s.pcapfilename,optarg);
				}
				else{
					printf("-r vyzaduje platny subor typu pcapng\n");
					exit(1);
				}
				}
				s.pcapfileset = 1;
				break;
		
			case '?':
				printf("Neplatny argument: %c \n", opt);
				exit(1);
		}
	}
	
	if(s.pcapfileset == s.interfaceSet){
		printf("Neplatne spustenie, treba zvolit bud pcap subor za moznostou -r alebo interface za moznostou -l, pre viac info spustite program s moznostou -h\n");
		exit(1);
	}
	
	if(s.interfaceSet == 1){
		//vyhladanie pristupnych zariadeni, na ktorich mozno zachytavat packety
		if((pcap_findalldevs(&interfaces, errbuf)) == PCAP_ERROR) {
				fprintf(stderr, "Couldn't find any device: %s\n", errbuf);
				exit(1);
		}
		/*
		//ak nebol zadany parameter pre argument -i vypisem mozne zariadenia
		if(s.interfaceSet == 0){
			for(iterator = interfaces; iterator != NULL; iterator = iterator->next){
				printf("%s %s \n",iterator->name, iterator->description);
			}
			exit(0);
		}
		*/
		//zistenie adresy a masky zvoleneho zariadenia
		if (pcap_lookupnet(s.interface, &net, &mask, errbuf) == -1) {
				printf("Couldn't get netmask for device %s: %s\n", s.interface, errbuf);
				net = 0;
				mask = 0;
			}

		//otvorenie spojenia pre zachytavanie packetov
		s.handle = pcap_open_live(s.interface, BUFSIZ, 1, 0, errbuf);
		if(s.handle == NULL){
			printf("Nemozno otvorit %s: %s \n",s.interface, errbuf );
			exit(1);
		}
		/*
		//vytvorenie a spustenie filtra 
		if (pcap_compile(s.handle, &fp, s.filter_exp, 0, net) == -1) {
				printf("Couldn't parse filter %s: %s\n", s.filter_exp, pcap_geterr(handle));
				exit(1);
		}
		if (pcap_setfilter(s.handle, &fp) == -1) {
				printf("Couldn't install filter %s: %s\n", s.filter_exp, pcap_geterr(handle));
				exit(1);
		}
		*/
	}
	else if(s.pcapfileset == 1){
		s.handle = pcap_open_offline(s.pcapfilename,errbuf);
		if(s.handle == NULL){
			printf("Nemozno otvorit %s: %s \n",s.pcapfilename, errbuf );
			exit(1);
		}
	}

		//vytvorenie a spustenie filtra 
	if (pcap_compile(s.handle, &fp, "tcp" , 0, net) == -1) {
			printf("Couldn't parse filter \"tcp\": %s\n", pcap_geterr(s.handle));
			exit(1);
	}
	if (pcap_setfilter(s.handle, &fp) == -1) {
			printf("Couldn't install filter \"tcp\": %s\n", pcap_geterr(s.handle));
			exit(1);
	}

	return s;
}

void process_transport_layer(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){

	char time[30];	//premenna pre ulozenie hodnoty casu
	int size = header->len;	//celkova velkost packetu
	struct iphdr *iph = (struct iphdr *)(buffer +  sizeof(struct ethhdr)); //ukazatel na ip hlavicku
	struct udphdr *udph;	//ukazatel na udp hlavicku
	struct tcphdr *tcph;	//ukazatel na tcp hlavicku
	int headerSize;			//velkost hlavicky packetu
	unsigned short iphdrlen; //velkost ip hlavicky
	struct hostent *h;		//
	int version = iph->version;	//ip verzia
	char ipv6_address[INET6_ADDRSTRLEN]; //IPv6 adresa
	struct ip6_hdr *ip6h;	//ukazatel na IPV6 hlavicku

	struct LLElem currPkt;
	LLElemPtr tempPtr;
	memset(&currPkt,0,sizeof(currPkt)); 
	

	//____________IPv4_____________
	if(version == 4){

		currPkt.ipvers = 4;

		//Spracovanie TCP packetu
		if(iph->protocol == 6){

			 /********
			
			strftime(time,30,"%X.",localtime(&header->ts.tv_sec));		//zistenie casu
			printf("%s%ld ",time,header->ts.tv_usec); 					//vypis casu
			
			*********/
			// ulozenie casu pre paket
			currPkt.secs = header->ts.tv_sec;
			currPkt.usecs = header->ts.tv_usec;

			iphdrlen = iph->ihl*4;							//velkost ip hlavicky
			/**

			memset(&source,0,sizeof(source));				//vycistenie pamate
			source.sin_addr.s_addr = iph->saddr;			//ziskanie adresy zdroja paketu

			**/
			currPkt.source.sin_addr.s_addr = iph->saddr;			//ziskanie adresy zdroja paketu

			/**
			//preklad zdrojovej ip adresy do hostent struktury
			h = gethostbyaddr((const void*)&source.sin_addr,sizeof(struct in_addr),AF_INET);

			//vypis adresy zdroja, IP adresa ak sa nepodarilo najst hostname
			if(h == NULL)
				printf("%s : ", inet_ntoa(source.sin_addr));
			else
				printf("%s : ", h->h_name);
			**/

			//vypocet ukazatela na tcp hlavicku a vypocet velkosti hlavicky packetu
			struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
			headerSize = sizeof(struct ethhdr) + iphdrlen + (tcph->doff * 4);

			currPkt.dest.sin_addr.s_addr = iph->daddr;			//ziskanie adresy ciela paketu
			currPkt.cPort = ntohs(tcph->source);

			/**
			//vypis zdrojoveho portu
			printf("%u > ",ntohs(tcph->source));

			memset(&dest,0,sizeof(dest));				//vycistenie pamate
			dest.sin_addr.s_addr = iph->daddr;			//ziskanie cielovej adresy
			
			

			

			//preklad cielovej ip adresy do hostent struktury
			h = gethostbyaddr((const void*)&dest.sin_addr,sizeof(struct in_addr),AF_INET);
			//vypis adresy ciela, IP adresa ak sa nepodarilo najst hostname
			if(h == NULL)
				printf("%s : ", inet_ntoa(dest.sin_addr));
			else
				printf("%s : ", h->h_name);
			**/
			//vypis cieloveho portu
			currPkt.sPort = ntohs(tcph->dest);
			
			
			
				
			if(tcph->fin){
				/*
				strftime(time,30,"%X.",localtime(&currPkt.secs));		//konvertovanie
				printf("Time is: %s%ld \n",time,currPkt.usecs); 					//vypis casu
				printf("Source IP/hostname: %s \n",inet_ntoa(currPkt.source.sin_addr));
				printf("Client port is %u \n", ntohs(currPkt.cPort));
				printf("Dest IP/hostname: %s \n",inet_ntoa(currPkt.dest.sin_addr));
				*/

				//memset(tempPtr,0,sizeof(tempPtr));
				//printf("skuska\n");
				//printf("source %u dest %u \n",currPkt.cPort,currPkt.sPort);
				tempPtr = FindComm(&comms,&currPkt);

				char time[30];	//premenna pre ulozenie hodnoty casu
				memset(time,0,sizeof(time));
				if(tempPtr != NULL){

					/*
					strftime(time,30,"%X.",localtime(&tempPtr->secs));		//konvertovanie
					printf("Brasko FIN doslo\n");
					printf("Time is: %s%ld \n",time,tempPtr->usecs); 					//vypis casu
					printf("Source IP/hostname: %s \n",inet_ntoa(tempPtr->source.sin_addr));
					printf("Client port is %u \n", ntohs(tempPtr->cPort));
					printf("Dest IP/hostname: %s \n",inet_ntoa(tempPtr->dest.sin_addr));
					printf("Number of bytes in communication: %lu\n",tempPtr->bytes);
					//
					*/

					if(comms.First != NULL) //overenie ci sa nema rusit prazdny zoznam
					{
						while(tempPtr->rptr != NULL) //cyklus na mazanie prvkov a uvolnenie alokovanej pamate
						{
							char time[30];	//premenna pre ulozenie hodnoty casu
							memset(time,0,sizeof(time));
							strftime(time,30,"%X.",localtime(&tempPtr->secs));		//konvertovanie
							printf("Time is: %s%ld \n",time,tempPtr->usecs); 					//vypis casu
							printf("Source IP/hostname: %s \n",inet_ntoa(tempPtr->source.sin_addr));
							printf("Client port is %u \n", ntohs(tempPtr->cPort));
							printf("Dest IP/hostname: %s \n",inet_ntoa(tempPtr->dest.sin_addr));
							printf("Number of bytes in communication: %lu\n",tempPtr->bytes);
							if(tempPtr->rptr == NULL)
							{
								
								printf("Kokotko\n");
								return;
							}
							//DeleteElement(&comms,tempPtr);
							tempPtr = tempPtr->rptr;
						}
						printf("\n Dorobil som print listu brasko \n");
					}
					//DeleteElement(&comms,tempPtr);

				}
			}
			else if(tcph->syn){
				printf("\nBrasko toto bol SYN packet\n");
				process_tls_header((buffer + headerSize),(size - headerSize), currPkt);
				/*
				strftime(time,30,"%X.",localtime(&currPkt.secs));		//konvertovanie
				printf("Time is: %s%ld \n",time,currPkt.usecs); 					//vypis casu
				printf("Source IP/hostname: %s \n",inet_ntoa(currPkt.source.sin_addr));
				printf("Client port is %u \n", ntohs(currPkt.cPort));
				printf("Dest IP/hostname: %s \n",inet_ntoa(currPkt.dest.sin_addr));
				*/
			}
			else{

				process_tls_header((buffer + headerSize),(size - headerSize), currPkt);
				//printf("\nBrasko toto bol ACK packet\n");
			}
			/*
			strftime(time,30,"%X.",localtime(&currPkt.secs));		//konvertovanie
			printf("Time is: %s%ld \n",time,currPkt.usecs); 					//vypis casu
			printf("Source IP/hostname: %s \n",inet_ntoa(currPkt.source.sin_addr));
			printf("Client port is %u \n", ntohs(currPkt.cPort));
			printf("Dest IP/hostname: %s \n",inet_ntoa(currPkt.dest.sin_addr));
			*/
		}
		else return;
	}
	//__________IPv6_____________

	else if( version == 6){
		struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer +  sizeof(struct ethhdr));
		

		//Spracovanie TCP packetu
		if(ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6){

			strftime(time,30,"%X.",localtime(&header->ts.tv_sec));		//zistenie casu
			printf("%s%ld ",time,header->ts.tv_usec); 					//vypis casu

			iphdrlen = 40;									//velkost ip hlavicky
			memset(&source6,0,sizeof(source));				//vycistenie pamate
			memset(&ipv6_address,0,sizeof(ipv6_address));
			source6.sin6_addr = ip6h->ip6_src;			//ziskanie adresy zdroja paketu

			//preklad zdrojovej ip adresy do hostent struktury
			h = gethostbyaddr((const void*)&source6.sin6_addr,sizeof(struct in6_addr),AF_INET6);

			//vypis adresy zdroja, IP adresa ak sa nepodarilo najst hostname
			if(h == NULL)
				printf("%s : ", inet_ntop(AF_INET6,&source6.sin6_addr, ipv6_address, INET6_ADDRSTRLEN));
			else
				printf("%s : ", h->h_name);

			//vypocet ukazatela na tcp hlavicku a vypocet velkosti hlavicky packetu
			struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
			headerSize = sizeof(struct ethhdr) + iphdrlen + (tcph->doff * 4);

			//vypis zdrojoveho portu
			printf("%u > ",ntohs(tcph->source));

			memset(&dest,0,sizeof(dest6));				//vycistenie pamate
			memset(&ipv6_address,0,sizeof(ipv6_address));
			dest6.sin6_addr = ip6h->ip6_dst;			//ziskanie cielovej adresy

			//preklad cielovej ip adresy do hostent struktury
			h = gethostbyaddr((const void*)&dest6.sin6_addr,sizeof(struct in6_addr),AF_INET6);
			//vypis adresy ciela, IP adresa ak sa nepodarilo najst hostname
			if(h == NULL)
				printf("%s : ", inet_ntop(AF_INET6,&dest6.sin6_addr, ipv6_address, INET6_ADDRSTRLEN));
			else
				printf("%s : ", h->h_name);

			//vypis cieloveho portu
			printf("%u \n\n",ntohs(tcph->dest));

			if(tcph->fin){
				LLElemPtr tempPtr = FindComm(&comms,&currPkt);
				printf("\nBrasko toto bol FIN packet\n");
				/*
				if(tempPtr != NULL){
					char time[30];	//premenna pre ulozenie hodnoty casu
					memset(time,0,sizeof(time));
					strftime(time,30,"%X.",localtime(&tempPtr->secs));		//konvertovanie
					printf("Time is: %s%ld \n",time,tempPtr->usecs); 					//vypis casu
					printf("Source IP/hostname: %s \n",inet_ntoa(tempPtr->source.sin_addr));
					printf("Client port is %u \n", ntohs(tempPtr->cPort));
					printf("Dest IP/hostname: %s \n",inet_ntoa(tempPtr->dest.sin_addr));
					printf("Number of bytes in communication: %lu\n",tempPtr->bytes);
					//DeleteElement(&comms,tempPtr);
				}
				*/
				if(comms.First != NULL) //overenie ci sa nema rusit prazdny zoznam
				{
					while(tempPtr->rptr != NULL) //cyklus na mazanie prvkov a uvolnenie alokovanej pamate
					{
						char time[30];	//premenna pre ulozenie hodnoty casu
						memset(time,0,sizeof(time));
						strftime(time,30,"%X.",localtime(&tempPtr->secs));		//konvertovanie
						printf("Time is: %s%ld \n",time,tempPtr->usecs); 					//vypis casu
						printf("Source IP/hostname: %s \n",inet_ntoa(tempPtr->source.sin_addr));
						printf("Client port is %u \n", ntohs(tempPtr->cPort));
						printf("Dest IP/hostname: %s \n",inet_ntoa(tempPtr->dest.sin_addr));
						printf("Number of bytes in communication: %lu\n",tempPtr->bytes);
						tempPtr = tempPtr->rptr;
				}
	}
			}
			else if(tcph->syn){
				printf("\nBrasko toto bol SYN packet\n");
				process_tls_header((buffer + headerSize),(size - headerSize), currPkt);
			}
			else{
				printf("\nBrasko toto bol ACK packet\n");
				process_tls_header((buffer + headerSize),(size - headerSize), currPkt);
			}
		}
		else return;
		
	}
	else{
		printf("Neznama verzia ip packetu\n");
		exit(1);
	}

	
}




void process_tls_header(const u_char *data, int dataSize,struct LLElem currPkt){
	#define CHANGE_CIPHER_SPEC		20
	#define ALERT					21
	#define HANDSHAKE				22
	#define APPLICATION_DATA		23

	#define HELLO_REQUEST			00
   	#define CLIENT_HELLO			01
   	#define SERVER_HELLO			02
   	#define CERTIFICATE				11
   	#define SERVER_KEY_EXCHANGE 	12
   	#define CERTIFICATE_REQUEST		13
   	#define SERVER_DONE				14
   	#define CERTIFICATE_VERIFY		15
   	#define CLIENT_KEY_EXCHANGE		16
   	#define FINISHED				20

	int datapointer = 0;

	LLElemPtr tempPkt = FindComm(&comms,&currPkt);

	//printf("%02x \n",(unsigned int)data[datapointer]);
	//printf("%d \n",atoi((unsigned char)data[datapointer]));
	//printf("test1 \n");
	switch(data[datapointer]){
		case CHANGE_CIPHER_SPEC:
			printf("Im a TLS CHANGE_CIPHER_SPEC\n");
			datapointer++;
			if(data[datapointer] == 3){
				datapointer++;
				if(data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
					currPkt.bytes = (unsigned long)(data[datapointer]<<8)+data[datapointer+1];
					if(tempPkt != NULL){
								tempPkt->bytes = tempPkt->bytes + currPkt.bytes;
							}
				}
			}
			break;
		case ALERT:
			printf("Im a TLS ALERT\n");
			datapointer++;
			if(data[datapointer] == 3){
				datapointer++;
				if(data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
					currPkt.bytes = (unsigned long)(data[datapointer]<<8)+data[datapointer+1];
					if(tempPkt != NULL){
								tempPkt->bytes = tempPkt->bytes + currPkt.bytes;
							}
				}
			}
			break;
		case HANDSHAKE:
			printf("Im a TLS HANDSHAE\n");
			//printf("test2 \n");
			datapointer++;
			if(data[datapointer] == 3){
				datapointer++;
				if(data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
					//printf("Lenght from record layer: %hu \n",(unsigned short)(data[datapointer]<<8)+data[datapointer+1]);
					//printf("Lenght from record layer: %hu \n",(unsigned long)(data[datapointer]<<8)+data[datapointer+1]);
					currPkt.bytes = (unsigned long)(data[datapointer]<<8)+data[datapointer+1];
					datapointer = datapointer + 3;
					//printf("%02x \n",(unsigned int)data[datapointer]);
					switch(data[datapointer]){
						case CLIENT_HELLO:
							printf("prislo CLIENT_HELLO \n");
							LInsertLast(&comms,&currPkt);
							break;

						case HELLO_REQUEST:
						case SERVER_HELLO:

						case CERTIFICATE:

						case SERVER_KEY_EXCHANGE:

						case CERTIFICATE_REQUEST:

						case SERVER_DONE:

						case CERTIFICATE_VERIFY:

						case CLIENT_KEY_EXCHANGE:

						case FINISHED:
							if(tempPkt != NULL){
								tempPkt->bytes = tempPkt->bytes + currPkt.bytes;
							}
							break;
					}
				}
			}
			break;
		case APPLICATION_DATA:
			printf("Im a TLS APPLICATION_DATA\n");
			datapointer++;
			if(data[datapointer] == 3){
				datapointer++;
				if(data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
					if(tempPkt != NULL){
								tempPkt->bytes = tempPkt->bytes + currPkt.bytes;
							}
				}
			}
			break;
	}
}