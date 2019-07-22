#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

struct ethernet {
    u_char src_mac[6];
    u_char des_mac[6];
};
 struct ip{
     u_char src_ip[4];
     u_char des_ip[4];
 };

 struct port{
     u_char src_port[2];
     u_char des_port[2];
 };

 void print_p(const u_char *buf, int n)
 {
     for (int i = 0; i < n; ++i) {
         printf("%02x ", buf[i]);
     }
     printf("\n");
 }

 int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true){
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    struct ethernet e;
    e.src_mac[0]= packet[0];e.src_mac[1]= packet[1];e.src_mac[2]= packet[2];e.src_mac[3]= packet[3];e.src_mac[4]= packet[4];e.src_mac[5]= packet[5];
    e.des_mac[0]= packet[6];e.des_mac[1]= packet[7];e.des_mac[2]= packet[8];e.des_mac[3]= packet[9];e.src_mac[4]= packet[10];e.src_mac[5]= packet[11];
    //struct ethernet ;.scr_mac = &packet;

    struct ip i;
    i.src_ip[0] = packet[26];i.src_ip[1] = packet[27];i.src_ip[2] = packet[28];i.src_ip[3] = packet[29];
    i.des_ip[0] = packet[30];i.des_ip[1] = packet[31];i.des_ip[2] = packet[23];i.des_ip[3] = packet[33];
    struct port p;
    p.src_port[0] = packet[34];
    p.src_port[1] = packet[35];
    p.des_port[0] = packet[36];
    p.des_port[1] = packet[37];
              if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->len);
    printf("%u bytes cpatured\n",header->caplen);

    printf("Source Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", e.src_mac[0], e.src_mac[1], e.src_mac[2], e.src_mac[3],e.src_mac[4],e.src_mac[5]);
    printf("Destination Mac: %02x:%02x:%02x:%02x:%02x:%02x\n",e.des_mac[0],e.des_mac[1], e.des_mac[2], e.des_mac[3], e.des_mac[4],e.des_mac[5]);

    u_short tmp;
    u_short *ptmp = &tmp;
    *(ptmp+1) = packet[13];
    *ptmp = packet[12];
    u_short net_port = htons(tmp);
     if(net_port == 2048){
        printf("Next packet is IP\n");
    printf("Source IP : %d.%d.%d.%d\n",i.src_ip[0],i.src_ip[1],i.src_ip[2],i.src_ip[3]);
    printf("Destination IP :%d.%d.%d.%d\n",i.des_ip[0],i.des_ip[1],i.des_ip[2],i.des_ip[3]);
    }

     if(packet[23]==06)
  {
    printf("Next packet is TCP\n");
    printf("TCP data is ");
    print_p(&packet[66], 10);
    printf("TCP data Length: %d\n", packet[46]);
    }

    printf("Source port :%d\n",p.src_port[0]*256+p.src_port[1]);
    printf("Destination port: %d\n",p.des_port[0]*256+p.des_port[1]);
    printf("*************************************************\n");
  }
  pcap_close(handle);
  return 0;
}
