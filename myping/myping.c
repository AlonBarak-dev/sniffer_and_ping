// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
// 
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>


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
#include <sys/time.h> // gettimeofday()



 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click 
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.

#define SOURCE_IP "192.168.1.18"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "192.168.1.1"

int main ()
{
    //struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the ping.\n";        // the BUFFER

    int datalen = strlen(data) + 1;     // the length of the BUFFER 

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; 

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet 
    char packet[IP_MAXPACKET];

    // Next, ICMP header
    memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HDRLEN), ICMP_HDRLEN + datalen);
    memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);
    
    //~~~
    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;

    int flag = 1;       // a flag represents a successful capture or not


    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)        // if the socket creation failed
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // variables for time capturing
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec=0, total_msec=0;
    struct timeval tv_out;
    tv_out.tv_sec = 1;
    tv_out.tv_usec = 0;
  
    clock_gettime(CLOCK_MONOTONIC, &tfs);       // start counting

    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet, IP4_HDRLEN + ICMP_HDRLEN + datalen, 0,
     (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)  
    {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        flag = 0;       // set flag for failure
        return -1;
    }

    int addr_len=sizeof(dest_in);
    
    // if the receive process failed
    if (recvfrom(sock, &packet, sizeof(packet), 0, 
            (struct sockaddr*)&dest_in, &addr_len) <= 0) 
    {
        printf("\nPacket receive failed!\n");
    }
    // if the receive process successed 
    else
    {
        // end of RTT, stop counting
        clock_gettime(CLOCK_MONOTONIC, &time_end);
        // calculating the RTT (round-trip-time)
        double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0;
        rtt_msec = (time_end.tv_sec-time_start.tv_sec) + timeElapsed;
            
        // if packet was not sent, don't receive
        if(flag)
        {
            printf("%Lf \n", rtt_msec);
            printf("%s \n", data);
        }
    }    
    // ~~~
    // Close the raw socket descriptor.
    close(sock);
    
    return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}
