/*
*Author: Mihir Pattani
*Penn Key: 63859942
*Course: Networked Systems CIS-553
*Assignment 2: Network Analysis
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h> 
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <limits.h>


#define ETHERNET_ADDRESS_LENGTH	6
#define IP_ADDRESS_LENGTH 4
#define TWO_BYTES 2
#define FOUR_BYTES 4
#define TCP 6
#define UDP 17

typedef unsigned char BYTE;
typedef unsigned short U16;
typedef unsigned int U32;

//ethernet header structure
typedef struct eth_header{
    	BYTE dest_address[ETHERNET_ADDRESS_LENGTH];
	BYTE src_address[ETHERNET_ADDRESS_LENGTH];
    	BYTE ether_type[TWO_BYTES];
}eth_header;

//ip header structure
typedef struct ip_header{
    	BYTE v_ihl;
	BYTE service;
    	BYTE total_len[TWO_BYTES];
    	BYTE identification[TWO_BYTES];
    	BYTE offset[TWO_BYTES];
    	BYTE ttl;
	BYTE protocol;
    	BYTE checksum[TWO_BYTES];
    	BYTE src_address[IP_ADDRESS_LENGTH];
    	BYTE dest_address[IP_ADDRESS_LENGTH];
}ip_header;

//tcp header structure
typedef struct tcp_header{
	BYTE src_port[TWO_BYTES];
	BYTE dest_port[TWO_BYTES];
	BYTE seq_num[FOUR_BYTES];
	BYTE ack[FOUR_BYTES];
	BYTE offset_reserved_flag[TWO_BYTES];
	BYTE window_size[TWO_BYTES];
	BYTE checksum[TWO_BYTES];
	BYTE urgent[TWO_BYTES];
	BYTE options[40];	 
}tcp_header;

//udp header structure
typedef struct udp_header{
	BYTE src_port[TWO_BYTES];
	BYTE dest_port[TWO_BYTES];
	BYTE length[TWO_BYTES];
	BYTE checksum[TWO_BYTES];	
}udp_header;

//struct to store general information about the pcap file
typedef struct pcap_info{
	int total_packets;
	int tcp_count;
	int udp_count;
	int other_count;
}pcap_info;

//struct to store info about particular packet
typedef struct packet_data{
	int packet_number;
	int protocol;
	BYTE src_MAC_address[ETHERNET_ADDRESS_LENGTH];
	BYTE dest_MAC_address[ETHERNET_ADDRESS_LENGTH];
	BYTE src_ip_address[IP_ADDRESS_LENGTH];
	BYTE dest_ip_address[IP_ADDRESS_LENGTH];	
	int src_port;
	int dest_port;
	int checksum;
	int valid;
	int payload;
}packet_data;

//declaration for function to generate checksum 
U16 generate_checksum(U16 tcp_data[], U16 src_ip[], U16 dest_ip[], U16 tcp_length);

//declaration for funstion to print data
void print_packet_data(packet_data data);

int main(int argc, char *argv[]){
	pcap_t *pcap;
	const BYTE *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	int packet_num = 0;
	eth_header *ethernet;
	ip_header *ip;
	pcap_info stats = {0, 0, 0, 0};
	packet_data data = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	int ip_header_length;
	int i, j;
	
	//check for correct input
	if (argc != 2){
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
	}
	
	//read pcap file
    	if ((pcap = pcap_open_offline(argv[1],errbuf)) == NULL){
        	fprintf(stderr, "ERROR: reading pcap file %s- %s\n", argv[0], errbuf);
        	exit(1);
    	}

	//loop over all packets
	for(packet_num = 0; (packet = pcap_next(pcap, &header)) != NULL; packet_num++){
 		data.packet_number = packet_num + 1;
		
		//map ethernet header of packet to the eth_header struct
		ethernet = (eth_header *)(packet);
		
		//length of ethernet header always considered 14 bytes
		int ethernet_header_length = sizeof(eth_header);
		
		//save MAC addresses in packet_data struct
		for(i = 0; i < 6; i++){
			data.src_MAC_address[i] = (BYTE) ethernet->src_address[i];
			data.dest_MAC_address[i] = (BYTE) ethernet->dest_address[i];
		}
		
		//map ip header to ip_header struct
		ip = (ip_header *) (packet + ethernet_header_length); 
		
		//calculate ip header length
		ip_header_length = ((ip->v_ihl) & 0x0F);
		ip_header_length = ip_header_length * 4;
		
		//save ip addresses to packet_data struct
		for(i = 0; i < 4; i++){
			data.src_ip_address[i] = (BYTE) ip->src_address[i];
			data.dest_ip_address[i] = (BYTE) ip->dest_address[i];
		}
		
		// start transport layer processing
		int transport_header_length = 0;
		int payload_length = 0;
 		
 		if(ip->protocol == 6){
 			//TCP
 			data.protocol = 6;
			stats.tcp_count++;
			
			//map tcp header to tcp_header struct
			tcp_header *tcp = (tcp_header*)(packet + ethernet_header_length + ip_header_length);
			
			//TCP header length
			transport_header_length = ((*(tcp->offset_reserved_flag) & 0xF0) >> 4)*4;

			//Actual payload / data length			
			payload_length = header.len - (ethernet_header_length + ip_header_length + transport_header_length);
			
			//calculate and save ports
			U16 src_port = *((U16*)tcp->src_port);	
			src_port = src_port >> 8 | src_port << 8;
			data.src_port = src_port;		

			U16 dest_port = *((U16*)tcp->dest_port);
			dest_port = dest_port >> 8 | dest_port << 8;
			data.dest_port = dest_port;
			
			//get chechsum value from packet
			U16 checksum = *((U16*)tcp->checksum);
			checksum = checksum >> 8 | checksum << 8;
			data.checksum = checksum;
			
			//generate checksum value
			//saving all data in unsigned short format as checksum is over 16 bits
			U16 tcp_length = (U16)payload_length + (U16)transport_header_length; 
			U16 tcp_data[tcp_length];
			U16 src_ip[4];
			U16 dest_ip[4];
			const BYTE *tcp_pointer = (const BYTE *)(packet + ethernet_header_length + ip_header_length);

			for(j = 0; j < tcp_length; j++){
				tcp_data[j] = (U16)*(tcp_pointer+j);
			}
			
			for(j = 0; j < 4; j++){
				src_ip[j] = (U16) ip->src_address[j];
				dest_ip[j] = (U16) ip->dest_address[j];
			}
			
			//call to checksum generating function
			U16 checksum_calc = generate_checksum(tcp_data, src_ip, dest_ip, tcp_length); 

			// validate the 2 checksums
			if((int)checksum_calc == checksum){
				data.valid = 1;
			}	 
			
		}
		else if(ip->protocol == 17){
			//UDP
			data.protocol = 17;
			stats.udp_count++;
			
			//map udp header to udp_header struct
			udp_header *udp = (udp_header*)(packet + ethernet_header_length + ip_header_length);
			
			//udp header length is fixed size = 8 bytes
			transport_header_length = 8;
			
			//real payload/ data length in bytes
			payload_length = header.len - (ethernet_header_length + ip_header_length + transport_header_length);
			
			//process and save port data
			U16 src_port = *((U16*)udp->src_port);	
			src_port = src_port >> 8 | src_port << 8;
			data.src_port = src_port;
			
			U16 dest_port = *((U16*)udp->dest_port);
			dest_port = dest_port>>8 | dest_port<<8;
			data.dest_port = dest_port;
		}
		else{        	
			//identify other protocol (non TCP/UDP)
			data.protocol = -1;
			stats.other_count++;
			
			//Payload length is packet len - eth_headet - ip_header
			payload_length = header.len - (ethernet_header_length + ip_header_length);
		}

		data.payload = payload_length;
		
		print_packet_data(data);
	}
	stats.total_packets = packet_num;
	printf("\n_____________________________________________\n\n\tOverall Statistics\n_____________________________________________\n\n");
	printf("Total Packets:\t|\t%d\nTCP Packets:\t|\t%d\nUDP Packets:\t|\t%d\nOther Packets:\t|\t%d\n\n", stats.total_packets, stats.tcp_count, stats.udp_count, stats.other_count); 
	return 0;
}

//Function to print data stored in packet_data struct
void print_packet_data(packet_data data){
	int i = 0;
	printf("\n_____________________________________________\n\n\tPacket Number: %d\n_____________________________________________\n\n", data.packet_number);
	
	if(data.protocol == TCP){
		printf("Packet Type:\t|\tTCP\n");
	}
	else if(data.protocol == UDP){
		printf("Packet Type:\t|\tUDP\n");
	}
	else{
		printf("Packet Type:\t|\tother\n");
	}
	
	printf("MAC src:\t|\t");
	for(i = 0; i < 6; i++)
	{
		if(i < 5){
	    		printf("%02x:", data.src_MAC_address[i]);
		}
		else{
			printf("%02x0", data.src_MAC_address[i]);
		}
	}


	printf("\nMAC dest:\t|\t");
	for(i = 0; i < 6; i++)
	{
		if(i < 5){
	    		printf("%02x:", data.dest_MAC_address[i]);
		}
		else{
			printf("%02x", data.dest_MAC_address[i]);
		}
	}
	
	printf("\b\nIP src:\t\t|\t");
        for (i = 0; i < 4; i++)
        {
            	if(i < 3){
			printf("%d:", data.src_ip_address[i]);
		}
		else{
			printf("%d ", data.src_ip_address[i]);
		}
        }
        
        printf("\nIP dest:\t|\t");
        for (i = 0; i < 4; i++)
        {
		if(i < 3){
			printf("%d:", data.dest_ip_address[i]);
		}
		else{
			printf("%d", data.dest_ip_address[i]);
		}
        }
	printf("\nSrc port:\t|\t%d\n", data.src_port);
	printf("Dest port:\t|\t%d\n", data.dest_port);
        
        if(data.protocol == TCP){
        	printf("Checksum:\t|\t%d\n", data.checksum);
        	if(data.valid == 1){
        	      	printf("Validity:\t|\tValid Checksum\n");
        	}
        	else
        		printf("Validity:\t|\tInvalid Checksum\n");
        }
        printf("Payload :\t|\t%d\n", data.payload);
        printf("\n");
}

//Function to calculate checksum
U16 generate_checksum(U16 tcp_data[], U16 src_ip[], U16 dest_ip[], U16 tcp_length){
	//32 bit sum variable to accomodate for carry overs
	U32 sum = 0;
	U16 proto = 6;
	U16 word16 = 0;
	int i = 0;
	//add all parts of tcp header
	for(i = 0; i < (int)tcp_length; i = i + 2){
		U16 tmp1, tmp2;
		//avoid adding the checksum itself
		if(i == 16)
			continue;
		//join 8 bit words to form 16 bit ones. If odd number of words then padd with 0
		if(i == ((int)tcp_length - 1)){
			tmp1 = ((tcp_data[i]<<8) & 0xFF00);
			tmp2 = 0;
		}
		else{
			tmp1 = ((tcp_data[i]<<8) & 0xFF00);
			tmp2 = (tcp_data[i+1] & 0x00FF);
		}
		word16 = tmp1 + tmp2;
		sum = sum + (int)word16;
	}
	word16 = 0;
	//add false header fields
	for(i = 0; i < 4; i = i + 2){
		word16 = ((src_ip[i]<<8) & 0xFF00) + (src_ip[i+1] & 0x00FF);
		sum = sum + (int)word16;
	}
	for(i = 0; i < 4; i = i + 2){
		word16 = ((dest_ip[i]<<8) & 0xFF00) + (dest_ip[i+1] & 0x00FF);
		sum = sum + (int)word16;
	}
	sum = sum + (int)proto;
	sum = sum + (int)tcp_length;
	
	//carry over bits
	while (sum >> 16){
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	//bring size down to bits
	U16 new_sum = (U16)sum;
	//one's complement
	new_sum = (U16)(USHRT_MAX - new_sum);
	return new_sum;
}
