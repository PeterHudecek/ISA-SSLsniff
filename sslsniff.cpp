#include <stdio.h>
#include <stdlib.h>
#include <iostream>
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
#include <vector>

struct communication {
		struct sockaddr_in source,dest; 	/* ipv4 client a server ip */
		struct sockaddr_in6 source6, dest6; /* ipv6 klient a server ip */
		int ipvers;							/*flag na ip verziu */
		__u16   cPort; 						/* client port number */
		__u16   sPort; 						/* server port number */
		int cHelloFlg;						/* flag ci v komunikacii prislo Client Hello*/
		int sHelloFlg;						/* flag ci v komunikacii prislo Server Hello*/
		char SNI[200];						/* Server name indication */
		int packetNum;						/*pocet paketov */
		int finflag;						/* flag ktory znaci ci prisiel prvy tcp fin */
		unsigned long long bytes;			/* pocet bytov */
		long secs;							/* pcoet sekund */
		long usecs;							/*pocet mikrosekund */
};

struct isaSettings
{			
	int interfaceSet;		//flag ci bolo urcene zariadenie
	char interface[30];		//nazov zariadenia
	int pcapfileset;		//flag ci bol urceny pcap subor
	pcap_t *handle;			//pointer na pcap spojenie
	char pcapfilename[50];	//nazov suboru
};


std::vector<communication> communications; /* vector vsetkych komunikacii  */
//Funkcia pre spracovanie argumentov zo vstupu a uloženie ich do struktury
//Funkcia vracia strukturu s nastavenim packet snifferu
struct isaSettings setSettings(struct isaSettings s, int argc, char *argv[]);
//Callback funkcia pre pcap_loop(), funkcia spracuje zachyteny paket a vytlaci ho na stdout 
void process_transport_layer(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
//funkcia na spracovanie tsl headeru
void process_tls_header(const u_char *data, int dataSize, int commindex, struct communication);
//funkcia na vytlacenie komunikacie na stdout
void print_communication(communication comm,communication end);


int main(int argc, char *argv[])
{	
	struct isaSettings s = setSettings(s, argc, argv);
	//cyklus pre zachytavanie packetov
	pcap_loop(s.handle,-1,process_transport_layer, NULL);

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

	int commindex = -1;
	struct communication currPkt;
	memset(&currPkt,0,sizeof(currPkt)); 
	

	//____________IPv4_____________
	if(version == 4){

		currPkt.ipvers = 4;

		//Spracovanie TCP packetu
		if(iph->protocol == 6){

			// ulozenie casu pre paket
			currPkt.secs = header->ts.tv_sec;
			currPkt.usecs = header->ts.tv_usec;

			iphdrlen = iph->ihl*4;							//velkost ip hlavicky

			currPkt.source.sin_addr.s_addr = iph->saddr;			//ziskanie adresy zdroja paketu

			//vypocet ukazatela na tcp hlavicku a vypocet velkosti hlavicky packetu
			struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
			headerSize = sizeof(struct ethhdr) + iphdrlen + (tcph->doff * 4);
			currPkt.dest.sin_addr.s_addr = iph->daddr;			//ziskanie adresy ciela paketu
			currPkt.cPort = ntohs(tcph->source);
			currPkt.sPort = ntohs(tcph->dest);
			
				
			if(tcph->fin || tcph->rst){
				
				for(int i = 0; i < communications.size(); i++)
				{

					if(communications[i].cPort == currPkt.cPort || communications[i].cPort == currPkt.sPort)
					{	

						commindex = i;
						break;
					}
				}
				if(commindex != -1)
				{
					communications[commindex].packetNum++;
					process_tls_header((buffer + headerSize),(size - headerSize),commindex ,currPkt);

					if(tcph->rst || communications[commindex].finflag == 1)
					{
						if(communications[commindex].cHelloFlg == 1 && communications[commindex].sHelloFlg == 1)
							print_communication(communications[commindex],currPkt);

						communications.erase(communications.begin() + commindex);
					}
					else if(communications[commindex].finflag == 0)
						communications[commindex].finflag++;		
				}
				
			}
			else if(tcph->syn && !tcph->ack){

				for(int i = 0; i < communications.size(); i++)
				{
					if(communications[i].cPort == currPkt.cPort || communications[i].cPort == currPkt.sPort)
					{
						commindex = i;
						break;
					}
				}
				if(commindex == -1)
				{	
					communications.push_back(currPkt);
					communications[communications.size() - 1].packetNum = 1;
					communications[communications.size() - 1].finflag = 0;
					communications[communications.size() - 1].cHelloFlg= 0;
					communications[communications.size() - 1].sHelloFlg = 0;
					process_tls_header((buffer + headerSize),(size - headerSize),communications.size() - 1,currPkt);

				}

			}
			else{

				for(int i = 0; i < communications.size(); i++)
				{
					if(communications[i].cPort == currPkt.cPort || communications[i].cPort == currPkt.sPort)
					{
						commindex = i;
						break;
					}
				}
				if(commindex != -1)
				{
					communications[commindex].packetNum++;
					process_tls_header((buffer + headerSize),(size - headerSize),commindex ,currPkt);
				}
			}
		}
		else return;
	}

	//__________IPv6_____________

	else if( version == 6){

		struct ip6_hdr *ip6h = (struct ip6_hdr *)(buffer +  sizeof(struct ethhdr));

		//Spracovanie TCP packetu
		if(ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt == 6){

			iphdrlen = 40;									//velkost ip hlavicky
			//vypocet ukazatela na tcp hlavicku a vypocet velkosti hlavicky packetu
			struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
			headerSize = sizeof(struct ethhdr) + iphdrlen + (tcph->doff * 4);

			currPkt.ipvers = 6;									//ulozenie ipverzie
			currPkt.secs = header->ts.tv_sec;					//ulozenie casu paketu
			currPkt.usecs = header->ts.tv_usec;					//ulozenie mikrosekund
			currPkt.cPort = ntohs(tcph->source);				//ulozenie zdrojoveho portu
			currPkt.sPort = ntohs(tcph->dest);					//vypis cieloveho portu
			currPkt.source6.sin6_addr = ip6h->ip6_src;;			//ziskanie adresy zdroja paketu
			currPkt.dest6.sin6_addr = ip6h->ip6_dst;			//ziskanie cielovej adresy

			if(tcph->fin || tcph->rst){
				
				for(int i = 0; i < communications.size(); i++)
				{

					if(communications[i].cPort == currPkt.cPort || communications[i].cPort == currPkt.sPort)
					{	
						commindex = i;
						break;
					}
				}

				if(commindex != -1)
				{
					process_tls_header((buffer + headerSize),(size - headerSize),commindex ,currPkt);
					communications[commindex].packetNum++;
					if(tcph->rst || communications[commindex].finflag == 1)
					{
						if(communications[commindex].cHelloFlg == 1 && communications[commindex].sHelloFlg == 1)
							print_communication(communications[commindex],currPkt);

						communications.erase(communications.begin() + commindex);
					}
					else if(communications[commindex].finflag == 0)
					{
						communications[commindex].finflag++;
					}
				}
			}
			else if(tcph->syn && !tcph->ack){

				for(int i = 0; i < communications.size(); i++)
				{
					if(communications[i].cPort == currPkt.cPort || communications[i].cPort == currPkt.sPort)
					{
						commindex = i;
						break;
					}
				}
				if(commindex == -1)
				{	
					communications.push_back(currPkt);
					communications[communications.size() - 1].packetNum = 1;
					communications[communications.size() - 1].finflag = 0;
					communications[communications.size() - 1].cHelloFlg= 0;
					communications[communications.size() - 1].sHelloFlg = 0;
					process_tls_header((buffer + headerSize),(size - headerSize),communications.size() - 1 ,currPkt);

				}
			}
			else{
				for(int i = 0; i < communications.size(); i++)
				{
					if(communications[i].cPort == currPkt.cPort || communications[i].cPort == currPkt.sPort)
					{
						commindex = i;
						break;
					}
				}
				if(commindex != -1)
				{
					communications[commindex].packetNum++;
					process_tls_header((buffer + headerSize),(size - headerSize),commindex ,currPkt);
				}
			}
		}
		else return;
	}
	else{
		printf("Neznama verzia ip packetu\n");
		exit(1);
	}	
}

void process_tls_header(const u_char *data, int dataSize, int commindex , struct communication currPkt){
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

	while(datapointer < dataSize )
	{
		switch(data[datapointer]){
			case CHANGE_CIPHER_SPEC:
				datapointer++;
				if(data[datapointer] == 3){
					datapointer++;
					if(data[datapointer] == 0 || data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
						datapointer++;
						currPkt.bytes = (unsigned long)(data[datapointer]<<8)+data[datapointer+1];
						communications[commindex].bytes = communications[commindex].bytes + currPkt.bytes;
					}
				}
				break;
			case ALERT:
				datapointer++;
				if(data[datapointer] == 3){
					datapointer++;
					if(data[datapointer] == 0 || data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
						datapointer++;
						currPkt.bytes = (unsigned long)(data[datapointer]<<8)+data[datapointer+1];
						communications[commindex].bytes = communications[commindex].bytes + currPkt.bytes;
					}
				}
				break;
			case HANDSHAKE:
				datapointer++;
				if(data[datapointer] == 3){
					datapointer++;
					if(data[datapointer] == 0 || data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
						datapointer++;
						currPkt.bytes = (unsigned long)(data[datapointer]<<8)+data[datapointer+1];
						communications[commindex].bytes = communications[commindex].bytes + currPkt.bytes;
						datapointer = datapointer + 2;
						switch(data[datapointer]){
							case CLIENT_HELLO:
									communications[commindex].cHelloFlg = 1;
									communications[commindex].cPort = currPkt.cPort;
									communications[commindex].ipvers = currPkt.ipvers;
									if(currPkt.ipvers == 4){
										communications[commindex].source = currPkt.source;
										communications[commindex].dest = currPkt.dest;
									}
									else{
										communications[commindex].source6 = currPkt.source6;
										communications[commindex].dest6 = currPkt.dest6;
									}
								
								datapointer = datapointer + (unsigned short)data[datapointer + 38];
								memset(communications[commindex].SNI,0,sizeof(char)*200);
								for(datapointer;datapointer < dataSize;datapointer++)
								{
									if(data[datapointer] == 0x00 && data[datapointer+1] == 0x00)
									{
										datapointer = datapointer+2;
										int x = 0;
										while(data[datapointer] != 0x00)
										{	
											datapointer++;
											if(data[datapointer] > 32 && data[datapointer] < 127)
											{
												communications[commindex].SNI[x] = data[datapointer];
												x++;
											}	
										}
									}
								}
								break;
							case SERVER_HELLO:
								communications[commindex].sHelloFlg = 1;
							case HELLO_REQUEST:
							case CERTIFICATE:
							case SERVER_KEY_EXCHANGE:
							case CERTIFICATE_REQUEST:
							case SERVER_DONE:
							case CERTIFICATE_VERIFY:
							case CLIENT_KEY_EXCHANGE:
							case FINISHED:
								break;
						}
					}
				}
				break;
			case APPLICATION_DATA:
				datapointer++;
				if(data[datapointer] == 3){
					datapointer++;
					if(data[datapointer] == 0 || data[datapointer] == 1 || data[datapointer] == 2 || data[datapointer] == 3 || data[datapointer] == 4){
						datapointer++;
						currPkt.bytes = (unsigned long)(data[datapointer]<<8)+data[datapointer+1];
						communications[commindex].bytes = communications[commindex].bytes + currPkt.bytes;
					}
				}
				break;
			default:
				datapointer++;
				break;	
		}
	}
}
void print_communication(communication comm,communication end)
{
	char time[30];	//premenna pre ulozenie hodnoty casu
	char ipv6_address[INET6_ADDRSTRLEN]; //IPv6 adresa

	memset(time,0,sizeof(time));
	strftime(time,30,"%Y-%m-%d %H:%M:%S",localtime(&comm.secs));	//konvertovanie casu
	printf("%s.%06ld,",time,comm.usecs); 		//vypis casu

	/*vypis client ip, client port a server ip pre ipv4*/
	if(comm.ipvers == 4)
	{
		printf("%s,",inet_ntoa(comm.source.sin_addr));
		printf("%u,", comm.cPort);
		printf("%s,",inet_ntoa(comm.dest.sin_addr));
	}
	/*vypis client ip, client port a server ip pre ipv6*/
	else if(comm.ipvers == 6)
	{
		memset(&ipv6_address,0,sizeof(ipv6_address));
		inet_ntop(AF_INET6,&comm.source6.sin6_addr, ipv6_address, INET6_ADDRSTRLEN);
		printf("%s,", ipv6_address);
		printf("%u,", comm.cPort);
		memset(&ipv6_address,0,sizeof(ipv6_address));
		inet_ntop(AF_INET6,&comm.dest6.sin6_addr, ipv6_address, INET6_ADDRSTRLEN);
		printf("%s,", ipv6_address);
	}

	std::cout << comm.SNI;			//vypis SNI
	printf(",%lu,",comm.bytes);		//vypis poctu bytov
	printf("%d,", comm.packetNum);	//vypis poctu paketov
	/********vypocet trvania komunikacie*********************/
	if (end.usecs < comm.usecs)
	{
	    int nsec = (comm.usecs - end.usecs) / 1000000 + 1;
	    comm.usecs -= 1000000 * nsec;
	    comm.secs += nsec;
	}
	if (end.usecs - comm.usecs > 1000000)
	{
	    int nsec = (end.usecs - comm.usecs) / 1000000;
	    comm.usecs += 1000000 * nsec;
	    comm.secs -= nsec;
	}
	long duration_secs = end.secs - comm.secs;
	long duration_usecs = end.usecs - comm.usecs;
	/*********************************************************/
	printf("%ld.%06ld\n", duration_secs , duration_usecs);	//vypis trvania komunikacie
}