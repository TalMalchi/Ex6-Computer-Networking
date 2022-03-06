#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


int i=0;
unsigned short check_sum(unsigned short *ptr,int nbytes) //calculate checksum. check if there is no errors

{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{

// Snoofed packet struct
  struct ethhdr *eth = (struct ethhdr *)packet;
  struct ip *ip1 = (struct ip *)(packet + sizeof(struct ethhdr));
  struct icmphdr *icmp_hdr = (struct icmphdr*)(packet+sizeof(struct ethhdr)+sizeof(struct ip));

  int packet_len = ntohs(ip1->ip_len);

unsigned char * payload = (unsigned char *)packet+sizeof(struct ethhdr)+sizeof(struct ip)+sizeof(struct icmphdr);

    int payload_size = packet_len-(sizeof(struct ip)+sizeof(struct icmphdr));

    unsigned char temp[6];
    strcpy(temp,eth->h_source);
    strcpy(eth->h_source,eth->h_dest);
    strcpy(eth->h_dest,temp);

    struct in_addr *temp_addr = malloc(sizeof(struct in_addr));
    //set the data for the snoof packet
    *temp_addr = ip1->ip_dst;
    ip1->ip_dst=ip1->ip_src;
    ip1->ip_src = *temp_addr;
    ip1->ip_len = ntohs(ip1->ip_len);

    icmp_hdr->type=0;
    icmp_hdr->checksum=0;
    icmp_hdr->checksum=check_sum((unsigned short *)icmp_hdr,sizeof(struct icmphdr)+payload_size);

int enable = 1;
int sock = -1;


struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));

    dest_in.sin_family = AF_INET; //sending type
    dest_in.sin_addr.s_addr = ip1->ip_dst.s_addr; //reads ip destination interface

      //create raw socket
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return;
    }

    if((setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable)))==-1){
    fprintf (stderr, "sockopt() failed with error: %d", errno);
       return;
    }

if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST,&enable, sizeof(enable)) == -1) 
	{
		perror("setsockopt");
		return;
	}	
    printf("Sending....\n");
  //send the snoofer packets
  if((sendto(sock,ip1,ip1->ip_len,0,(struct sockaddr *)&dest_in,sizeof(dest_in)))==-1){
        fprintf (stderr, "could not send packet failed with error: %d", errno);
        perror("error");
        return;
    }
        printf("\t== Spoofed Packet Sent Successfully ==\t\n\n");
        close(sock);
}



int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype] = icmp-echo";
  bpf_u_int32 net;
  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); //Close the handle
  return 0;
}