#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

//create UDP header
struct psuedo_udp_header{
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t ph;
    u_int8_t proto;
    u_int16_t len;
};

//calculate checksum
unsigned short check_sum(unsigned short *ptr,int nbytes) 
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

int main(int argc, char const *argv[])
{
    int enable = 1;

    char buffer[4096],src_ip[32],*data; 
    memset(buffer, 0, 4096); 

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));

    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr("10.0.2.8");


    // Create RAW socket
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    if((setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable)))==-1){
    fprintf (stderr, "sockopt() failed with error: %d", errno);
        return -1;
    }

data = buffer + sizeof(struct iphdr) + sizeof(struct udphdr);
strcpy(data, "this message is spoofed");

 // Setting IP Header.
struct iphdr *ip= (struct iphdr *) buffer;
ip->version=4;
ip->ihl=5;
ip->ttl=255;
ip->saddr=inet_addr("1.2.3.4");
ip->daddr = dest_in.sin_addr.s_addr;
ip->protocol=   IPPROTO_UDP;
ip->check=0;
ip->frag_off=0;
ip->id=htons(33333);
ip->tot_len= sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);


// Calculate ip header checksum
ip->check = check_sum((unsigned short *) buffer,ip->tot_len);

 // Setting UDP Header
struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
udp->dest=htons(6789);
udp->source=htons(5555);
udp->len=htons(8+strlen(data));
udp->check=0;


//setting up psuedo-hdr needed for check sum
struct psuedo_udp_header psh;
psh.dst_addr = dest_in.sin_addr.s_addr;
psh.src_addr = inet_addr("1.2.3.4");
psh.proto = IPPROTO_UDP;
psh.ph = 0;
psh.len = htons(sizeof(struct udphdr)+strlen(data));

int psh_size = sizeof(struct psuedo_udp_header)+sizeof(struct udphdr)+strlen(data);
char *psd_hdr = malloc(psh_size);

memcpy(psd_hdr,(char*) &psh,sizeof(struct psuedo_udp_header));
memcpy(psd_hdr+sizeof(struct psuedo_udp_header),udp,sizeof(struct udphdr)+strlen(data));

// Calculate udp checksum
udp->check = check_sum((unsigned short *) psd_hdr, psh_size);


    if((sendto(sock,buffer,ip->tot_len,0,(struct sockaddr *)&dest_in,sizeof(dest_in)))==-1){
        fprintf (stderr, "could not send packet failed with error: %d", errno);
        perror("error");
        return -1;
    }
        close(sock);

return 0;
}

  
    