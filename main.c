//
// Created by akaimo on 2018/11/28.
//

#include <stdio.h>
#include <pcap.h>

#define DPCP_RCV_MAXSIZE   68
#define DPCP_PROMSCS_MODE  1
#define DPCP_RCV_TIMEOUT   1000
#define DPCP_NOLIMIT_LOOP  -1

void start_pktfunc(u_char *, const struct pcap_pkthdr *, const u_char *);

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
    printf("receive packet\n");
}
