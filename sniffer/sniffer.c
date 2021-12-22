#include "headers.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>


struct sockaddr_in source, dest; 


void PrintData (unsigned char* data , int Size)
{
	/*
	this method print the data/buffer of the packet.
	it prints onlt chars and numbers from the buffer.
	*/
	printf("	Data : ");
	for(int i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0) // pretty printing
		{
			for(int j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) //if its a number or alphabet				
					printf("%c",(unsigned char)data[j]); 
			}
		}
		
		if( i==Size-1)  
		{						
			for(int j=i-i%16 ; j<=i ; j++) //if its a number or alphabet				
			{
				if(data[j]>=32 && data[j]<=128) 
					printf("%c",(unsigned char)data[j]);
			}
			printf("\n");
		}
	}
}




void print_ip_header(unsigned char* Buffer, int Size)
{
	/*
	this method save and prints the IP header.
	*/
	unsigned short iphdrlen;
		
	struct iphdr *iph = (struct iphdr *)Buffer; // creating a ip header structure
	iphdrlen =iph->ihl*4;
	
	memset(&source, 0, sizeof(source)); // clear a space for the source ip
	source.sin_addr.s_addr = iph->saddr; // inserts the source ip from the header into source
	
	memset(&dest, 0, sizeof(dest)); // clear a space for the destination ip
	dest.sin_addr.s_addr = iph->daddr; // inserts the destination ip from the header into destination

	printf("	Source IP      : %s\n",inet_ntoa(source.sin_addr)); // prints the source ip
	printf("	Destination IP : %s\n",inet_ntoa(dest.sin_addr)); // prints the destination ip
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
	/*
	this method prints the ICMP packet
	*/
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer; // initialize a ip header structure from the Buffer pointer
	// if the packet protocol is not ICMP, ignore and exit
	if(iph->protocol != 1){
		return;
	}

	iphdrlen = iph->ihl*4;		// the length of the ip header
	
	// creates an ICMP header by combining the data in the buffer with data in the ip header
	struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen);		
				
	print_ip_header(Buffer , Size); //sends the ipheader data to be printed in an elegant manner.
	printf("	Type : %d\n",(unsigned int)(icmph->type)); //prints the packet's type
	printf("	Code : %d\n",(unsigned int)(icmph->code)); // prints the packet's code
	//prints the data stored in the packet
	PrintData(Buffer + iphdrlen + sizeof(icmph) , (Size - sizeof(icmph) - iph->ihl * 4)); 
}


int main()
{
	/*
	this is our main method, responsible for capturing packets 
	and printing it's contents.
	*/
	
	// socket attributes.
	int saddr_size , data_size, sock;
	struct sockaddr saddr;
	struct in_addr in;
	
	// a buffer that hold the packet's data.
	char buffer[512];
	
	printf("Listening for ICMP packets\n");
	//Create a raw socket that shall sniff, on ICMP.
	sock = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);
	// socket validation
	if(sock < 0)
	{
		printf("Socket Error\n");
		return 1;
	}
	// start listening
	int id = 1;
	while(1)
	{
		printf("Packet number: %d\n", id);
		id++;
		// Receive a packet from the socket
		data_size = recvfrom(sock , buffer , 512 , 0 , &saddr , &saddr_size);
		// receive validation
		if(data_size <0 )
		{
			printf("failed to get packets\n");
			return 1;
		}

		printf("Packet number: %d\n", id);
		id++;
		// prints the packet only if it's protocol is ICMP
        print_icmp_packet(buffer,data_size);
	}
	// close when finished.
	close(sock);

	printf("DONE");
	return 0;
}