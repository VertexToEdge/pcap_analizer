#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void extractMAC(const u_char *src,int offset){
    for(int i=0;i<6;i++){
        printf("%02x:",src[offset+i]);
    }
    printf("%02x",src[offset+6]);
}

void printMAC(const u_char *src,int offset,const char *macDir){
    
    printf("MAC %s :",macDir);
    extractMAC(src,offset);
    printf("\n");
}


void extractIPv4(const u_char *src, int offset){
    for(int i=0;i<3;i++){
        printf("%d.",src[offset+i]);
    }
    printf("%d",src[offset+4]);
}
void printIPv4(const u_char *src,int offset, const char *ipDir){
    printf("IPv4 %s :",ipDir);
    extractIPv4(src,offset);
    printf("\n");
}

void printTCPport(const u_char *src, int offset, const char *tcpDir){
    printf("TCP %s port : %d\n",tcpDir,src[offset]*256 + src[offset+1]);
}

void printData(const u_char *src, int offset,int packet_size){
    int size =( src[offset]>>4) +(( src[offset]&0xF)*16) ;
    //printf("!!!!!! %d %02x \n",size,src[offset]);
    int data_size =  packet_size - offset-12 + size*4;
    data_size = data_size>=16? 16:data_size;
    printf("\nData\n\t");
    for(int i=0;i<data_size;i++){
        printf("%02x ",src[offset+size*4 -12+ i]);
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
  int packet_cnt=0;
  while (true) {
    bool isTcp=false;
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    packet_cnt++;
    
    printf("=====%7d Idx %5u Size Packet=====\n",packet_cnt,header->caplen);
    printMAC(packet,0,"Destination");
    printMAC(packet,6,"Source");
    if (!(packet[12]==0x08 && packet[13] == 0x00)){
        printf("Who.... Sigh.... This packet(0x%02x%02x) is not IPv4.... Skip it\n\n",packet[12],packet[13]);
        
        if ((packet[12]==0x08 && packet[13] == 0x06))
            printf("\n ARP Packet\n");
        if ((packet[12]==0x08 && packet[13] == 0xdd))
            printf("\n IPv6 Packet\n");
    printf("=======================================\n\n");
        continue;
    }
    isTcp = false;
    if (packet[23] == 0x06){
        printf("\nTCP Packet!\n");
        isTcp = true;
    }
    if (packet[23] == 0x11){
        printf("\nUDP Packet!\n");
    }
    printIPv4(packet,26,"Source");
    printIPv4(packet,30,"Destination");
    int sizeIPheader = packet[14]&0xf ;    
    if (isTcp){
        printTCPport(packet,14+sizeIPheader*4 ,"Source");
        printTCPport(packet,14+sizeIPheader*4+2 ,"Destination");
    }
    printData(packet,14+sizeIPheader*4+12,header->caplen);
    //printf("%lu %u\n",sizeof(*packet),header->caplen);
    printf("=======================================\n\n");

  }

  pcap_close(handle);
  return 0;
}
