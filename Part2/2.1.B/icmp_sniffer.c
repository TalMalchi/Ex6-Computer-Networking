#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

//print the data of the sniff packets
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{

  struct ethhdr *eth = (struct ethhdr *)packet;


  struct ip *ip1 = (struct ip *)(packet + sizeof(struct ethhdr));
  printf("IP_src=%s , ", inet_ntoa(ip1->ip_src));
  printf("IP_dest=%s \n",inet_ntoa(ip1->ip_dst));
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp and host 8.8.8.8 and host 10.0.2.8"; // ICMP packets between two specific hosts
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