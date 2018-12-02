//
// Created by akaimo on 2018/11/28.
//

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <gvc.h>
#include <string>
#include <map>
#include <set>

void ethernetPacketHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void pppPacketHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void printPacket(const u_char *packet, u_int length);

static void usage(char *prog);

void generateGraph();

GVC_t *gvc;
Agraph_t *g;
std::map<std::string, std::set<std::string> > flows;

int main(int argc, char *argv[]) {
    char *pcap_file;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if ((pcap_file = argv[1]) == nullptr) {
        usage(argv[0]);
    };

    gvc = gvContext();
    g = agopen("sample", Agdirected, 0);

    pcap_t *handle = pcap_open_offline(pcap_file, error_buffer);
    if (handle == nullptr) {
        printf("error: open pcap file");
        return 1;
    }

//    /* 受信用のデバイスを開く */
//    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
//        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
//        exit(EXIT_FAILURE);
//    }
//    /* イーサネットのみ */
//    if (pcap_datalink(handle) != DLT_EN10MB) {
//        fprintf(stderr, "Device not support: %s\n", dev);
//        exit(EXIT_FAILURE);
//    }

    if (pcap_datalink(handle) == DLT_EN10MB) {
        if (pcap_loop(handle, 0, ethernetPacketHandler, nullptr) < 0) {
            exit(EXIT_FAILURE);
        }
    } else if (pcap_datalink(handle) == DLT_PPP) {
        if (pcap_loop(handle, 0, pppPacketHandler, nullptr) < 0) {
            exit(EXIT_FAILURE);
        }
    } else {
        printf("not support link type\n");
        exit(EXIT_FAILURE);
    }

    pcap_close(handle);

    generateGraph();

    return 0;
}

struct ppp_header {
    u_int ppp_header;
};

// 第1引数: pcap_loop関数の第4引数
//   2    : 受信したPacketの補足情報
//   3    : 受信したpacketへのポインタ
void ethernetPacketHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *) packet;
    struct ip *ip;

    if (ETHERTYPE_IP != ntohs(eth->ether_type)) {
        // IPパケットでない場合は無視
        return;
    }

    // Etherフレームデータの次がIPパケットデータなので、ポインタを移動させる。
    ip = (struct ip *) (packet + sizeof(struct ether_header));

    printf("ip_v = 0x%x\n", ip->ip_v);
    printf("ip_hl = 0x%x\n", ip->ip_hl);
    printf("ip_tos = 0x%.2x\n", ip->ip_tos);
    printf("ip_len = %d bytes\n", ntohs(ip->ip_len));
    printf("ip_id = 0x%.4x\n", ntohs(ip->ip_id));
    printf("ip_off = 0x%.4x\n", ntohs(ip->ip_off));
    printf("ip_ttl = 0x%.2x\n", ip->ip_ttl);
    printf("ip_p = 0x%.2x\n", ip->ip_p);
    printf("ip_sum = 0x%.4x\n", ntohs(ip->ip_sum));
    printf("ip_src = %s\n", inet_ntoa(ip->ip_src));
    printf("ip_dst = %s\n", inet_ntoa(ip->ip_dst));
    printf("\n");

    std::string src_ip = inet_ntoa(ip->ip_src);
    std::string dst_ip = inet_ntoa(ip->ip_dst);

    flows[src_ip].insert(dst_ip);
}

void pppPacketHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("ppp layer\n");
    struct ip *ip = (struct ip *) (packet + sizeof(struct ppp_header));
    printf("ip_src = %s\n", inet_ntoa(ip->ip_src));
    printf("ip_dst = %s\n", inet_ntoa(ip->ip_dst));
    printf("\n");

    std::string src_ip = inet_ntoa(ip->ip_src);
    std::string dst_ip = inet_ntoa(ip->ip_dst);

    flows[src_ip].insert(dst_ip);
}

void printPacket(const u_char *packet, u_int length) {
    for (int i = 0; i < length; i++) {
        if ((i % 16) == 0)
            printf("%#07x: ", i);    //Print Offset

        printf("%02x ", packet[i]);    //Print Data in Hex Format

        /* Print Data in ASCII Format */
        if (((i % 16) == 15) || (i == length - 1)) {
            for (int j = 0; j < 15 - (i % 16); j++)
                printf("   ");
            printf(" |");
            for (int j = (i - (i % 16)); j <= i; j++)
                if ((packet[j] > 31) && (packet[j] < 127)) {
                    printf("%c", packet[j]);
                } else {
                    printf(".");
                }
            printf("|\n");
        }
    }
}

static void usage(char *prog) {
    fprintf(stderr, "Usage: %s <pcap file>\n", prog);
    exit(EXIT_FAILURE);
}

void generateGraph() {
    for (std::pair<std::string, std::set<std::string> > flow:flows) {
        Agnode_t *src = ::agnode(g, (char *)flow.first.c_str(), 1);
        for(auto d : flow.second) {
            Agnode_t *dst = ::agnode(g, (char *)d.c_str(), 1);
            ::agedge(g, src, dst, 0, 1);
        }
    }

    gvLayout(gvc, g, "dot");
    gvRenderFilename(gvc, g, "png", "sample.png");
    gvRender(gvc, g, "dot", stdout);
}
