#include <iostream>
#include <unistd.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

using namespace std;

#pragma pack(push,1)
typedef struct Packet{
    uint8_t DesMac[6];
    uint8_t SrcMac[6];
    uint16_t Type;
    uint16_t HardwareT;
    uint16_t ProtocolT;
    uint8_t HardwareLen;
    uint8_t ProtocolLen;
    uint16_t Operation;
    uint8_t SenHardAdd[6];
    uint32_t SenIP;
    uint8_t TarHardAdd[6];
    uint32_t TarIP;
}P;
#pragma pack(pop)

struct ether_addr my_Mac;
struct sockaddr_in my_IP;

int getIP(char *dev){
    FILE* ptr;
    char cmd[300] = {0x0};
    char ip[21] = {0,};
    sprintf(cmd,"ifconfig | egrep 'inet addr:' | awk '{print $2}'",dev);
    ptr = popen(cmd,"r");
    fgets(ip,sizeof(ip),ptr);
    pclose(ptr);
    inet_aton(ip+5,&my_IP.sin_addr);
}

int get_mac(char *dev){
    FILE* ptr;
    char cmd[300] = {0x0};
    char Mac[20] = {0x0};
    sprintf(cmd,"ifconfig | grep HWaddr | grep %s | awk '{print $5}'",dev);
    ptr = popen(cmd,"r");
    fgets(Mac,sizeof(Mac),ptr);
    pclose(ptr);
    ether_aton_r(Mac,&my_Mac);

    return 0;
}



int main(int argc, char *argv[]){

    if(argc != 4){
        printf("That 's wrong!\n");
        printf("EX)./send_arp (interface) (senderIP) (targetIP) \n");
        exit(1);
    }
    char *dev = argv[1];
    getIP(dev);
    get_mac(dev);
    printf("My ip : %s \n", inet_ntoa(my_IP.sin_addr));
    printf("My mac ");
    for(int i = 0; i < 6; i++) printf(": %02x ",my_Mac.ether_addr_octet[i]);
    printf("\n");

    struct sockaddr_in sender_ip;
    struct sockaddr_in target_ip;
    uint32_t *senderIp;
    uint32_t *targettIp;
    inet_aton(argv[2],&sender_ip.sin_addr);
    inet_aton(argv[3], &target_ip.sin_addr);
    memcpy(&senderIp, &sender_ip.sin_addr, sizeof(uint32_t));
    memcpy(&targettIp, &target_ip.sin_addr, sizeof (uint32_t));

    struct pcap_pkthdr* header;
    const u_char* packet;
    char errorbuf[1024];
    pcap_t* handle = pcap_open_live(dev, 1024, 1, 1000, errorbuf);
    if (handle == NULL){
        printf("%s : %s \n", dev, errorbuf);
        exit(1);
    }


}

