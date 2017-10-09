#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include<net/if.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<netinet/in.h>

#define ethernet_header_len 14
#define ip4_header_len      20
#define arp_header_len      28

int main(int argc, char *argv[])
{
	pcap_t *handle;
	struct pcap_pkthdr *header;
	u_int8_t *interface = argv[1];
	u_int8_t attacker_mac[6];
	u_int8_t attacker_ip[4];
	u_int8_t sender_mac[6];
        u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
        u_int8_t target_ip[4];





	/*if(argc != 4)
	{
		printf("Syntax : ./send_arp <interface> <sender ip> <target ip\n>");
		return -1;
	}*/

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	
/*PART_1 : find attacker's ip and mac address*/

/*PART_2 : make arp packet (attacker -> sender)*/

/*PART_3 : get arp reply and find sender's mac address*/

/*PART_4 : make arp packet (attacker -> target)*/
 
/*PART_5 : get arp reply and find target's mac address*/

/*PART_6 : send fake arp reply packet to sender and change sender's arp table*/


















	
}















