//
// Created by akaimo on 2018/11/28.
//

#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>

#define DPCP_RCV_MAXSIZE   68
#define DPCP_PROMSCS_MODE  1
#define DPCP_RCV_TIMEOUT   1000
#define DPCP_NOLIMIT_LOOP  -1

void start_pktfunc(u_char *, const struct pcap_pkthdr *, const u_char *);

char *convmac_tostr(u_char *, char *, size_t);

int main() {
    pcap_t *pd = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];

    if ((pd = pcap_open_live("en0", DPCP_RCV_MAXSIZE, DPCP_PROMSCS_MODE, DPCP_RCV_TIMEOUT, ebuf)) == NULL) {
        exit(-1);
    }

    if (pcap_loop(pd, DPCP_NOLIMIT_LOOP, start_pktfunc, NULL) < 0) {
        exit(-1);
    }

    pcap_close(pd);
    return 0;
}

void start_pktfunc(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
    char dmac[18] = {0};
    char smac[18] = {0};
    struct ether_header *eth_hdr = (struct ether_header *) p;

    printf("ether header---------\n");
    printf("dest mac %s\n", convmac_tostr(eth_hdr->ether_dhost, dmac, sizeof(dmac)));
    printf("src mac %s\n", convmac_tostr(eth_hdr->ether_shost, smac, sizeof(smac)));
    printf("ether type %x\n\n", ntohs(eth_hdr->ether_type));
}

char *convmac_tostr(u_char *hwaddr, char *mac, size_t size) {
    snprintf(mac, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             hwaddr[0], hwaddr[1], hwaddr[2],
             hwaddr[3], hwaddr[4], hwaddr[5]);
    return mac;
}
