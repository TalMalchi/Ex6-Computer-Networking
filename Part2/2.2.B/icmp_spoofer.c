#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>

//check if there is no error // we have to get 16 time number 1, else - error
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

    char src_ip[32],*data; 
    

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

if (setsockopt (sock, SOL_SOCKET, SO_BROADCAST,&enable, sizeof(enable)) == -1) 
	{
		perror("setsockopt");
		return (0);
	}	

int payload = 64;
int buffer_size = sizeof(struct iphdr)+sizeof(struct icmphdr)+payload;
char buffer[buffer_size];
memset(buffer,0,sizeof(buffer));

 // Setting IP Header.
struct iphdr *ip= (struct iphdr *) buffer;
ip->version=4;
ip->ihl=5;
ip->ttl=255;
ip->saddr=inet_addr("1.2.3.4");
ip->daddr = dest_in.sin_addr.s_addr;
ip->protocol=   IPPROTO_ICMP;
ip->check=0;
ip->frag_off=0;
ip->id=rand();
ip->tot_len= sizeof (struct iphdr) + sizeof (struct icmphdr) + payload;


// Calculate ip header checksum
ip->check = check_sum((unsigned short *) buffer,ip->tot_len);

 // Setting Icmp Header
struct icmphdr *icmp_hdr = (struct icmphdr *) (buffer + sizeof(struct iphdr));
icmp_hdr->code=0;
icmp_hdr->type=ICMP_ECHO;
icmp_hdr->checksum=0;
icmp_hdr->un.echo.id= rand();
icmp_hdr->un.echo.sequence=rand();

memset(buffer + sizeof(struct iphdr) + sizeof(struct icmphdr), rand() % 255, payload);
icmp_hdr->checksum=check_sum((unsigned short*)icmp_hdr,sizeof(icmp_hdr)+payload);

        //send the spoofer packets
    if((sendto(sock,buffer,ip->tot_len,0,(struct sockaddr *)&dest_in,sizeof(dest_in)))==-1){
        fprintf (stderr, "could not send packet failed with error: %d", errno);
        perror("error");
        return -1;
    }
        close(sock);

return 0;
}

  
    