#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <netinet/if_ether.h>
#include <arpa/inet.h>



void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
 // printf("IN\n");
  struct ethhdr *eth = (struct ethhdr *)packet;
  struct ip *ip1 = (struct ip *)(packet + sizeof(struct ethhdr));
  struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ip) + sizeof(struct ethhdr));
  char *data=(u_char*)(packet + sizeof(struct ip) + sizeof(struct ethhdr)+sizeof(struct tcphdr));
  int size_data= ntohs(ip1->ip_len)- ( sizeof(struct ip) +sizeof(struct tcphdr));

  if (size_data>0)
  {
    //    printf("GOOD\n");
    for (size_t i = 0; i < size_data; i++)
    {
      if(isprint(*data)){
        printf("%c", *data);
      }
      data++;
    }
printf("\n");
    
  }
  
  // printf("IP_src=%s ," , inet_ntoa(ip1->ip_src) );
  // printf("IP_dest=%s",inet_ntoa(ip1->ip_dst) 
  
}

int main()
{
  pcap_t *handle; // מצביע לאורך החבילה והאורך שלה. אם ריקה נצא
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp and dst port 23";
  bpf_u_int32 net;
  //printf("first\n");

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
