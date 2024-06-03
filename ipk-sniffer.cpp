/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 */

// Project: VUT FIT IPK 2.projekt
// Author: Simona Ceskova xcesko00
// Date: 24.04.2022

#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
using namespace std;

// *************************************************************************************
// hlavicka ethernetu tvori 14 bytu
#define SIZE_ETHERNET 14

// hlavicka ethernetu
struct sniff_ethernet
{
    // adresu ethernetu tvori 6 bytu
    // dst MAC adresa - prvnich 6 bytu
    u_char ether_dhost[6];
    // src MAC adresa - druhych 6 bytu
    u_char ether_shost[6];
    // IPv4 0x0800, IPv6 0x86DD, arp 0x0806
    u_short ether_type;
};

struct ip6_hdr
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow; /* 4 bits version, 8 bits TC, 20 bits flow-ID */
            uint16_t ip6_un1_plen; /* payload length */
            uint8_t ip6_un1_nxt;   /* next header */
            uint8_t ip6_un1_hlim;  /* hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc; /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;
    struct in6_addr ip6_src; /* source address */
    struct in6_addr ip6_dst; /* destination address */
};

// hlavicka IP adreasy
struct sniff_ip
{
    u_char ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char ip_tos;                 /* type of service */
    u_short ip_len;                /* total length */
    u_short ip_id;                 /* identification */
    u_short ip_off;                /* fragment offset field */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_udp
{
    u_int16_t uh_sport; /* source port */
    u_int16_t uh_dport; /* destination port */
    u_int16_t uh_ulen;  /* udp length */
    u_int16_t uh_sum;   /* udp checksum */
};

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;   /* sequence number */
    tcp_seq th_ack;   /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
    u_char th_flags;
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};
// *************************************************************************************
// funkce na vypis napovedy
void print_help(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
    {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
        {
            printf("sudo ./ipk-sniffer /[-i rozhrani | --interface]{-p port}{[--tcp|-t][--udp|-u][--arp][--icmp]}{-n num}\n");
            printf("-i|--interface rozhrani udava v jakém rozhrani bude probihat prenos dat. Pri nezadání parametru, nebo jeho argumentu se vypise list moznych pouzitelných rozhrani.\n");
            printf("-p port uvada cislo platneho portu, pokud neni parametr zadan, tak bude prenos v rozmezi 0-65535.\n");
            printf("--tcp|-t, --udp|-u, --arp, --icmp pri nezadani ani jednoho parametru se automaticky vyberou vsechny. Je mozno zadat vice protokolu zároven.\n");
            printf("-n num pocet paket, ktery se vypise na stdin. Pri nezadani je automaticky roven jedne.\n");
            exit(0);
        }
    }
}

// kontrolovani zadavani, portu, protokolu a poctu paket, ktere se maji vypsat
;
string check_arg(int argc, char **argv, int *n)
{
    // pokud neni port zadan, tak defautne je to range ze vsem moznych portu
    string port = "range 0-65535)";
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0)
        {
            if ((i + 1) == (int)argc)
                exit(1);
            else
            {
                i++;
                // pokud je za parametrem -p jiny parametr a ne cislo portu
                if (strstr(argv[i], "-") != NULL)
                    exit(1);
                else
                    port = " " + (string)argv[i] + ")";
            }
        }
    }
    // pomocny bool pokud neni zadany protokol -> spojeni bude probihat na vsech
    bool parameters = true;
    string str;
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0)
        {
            parameters = false;
            // pokud je v promenne str uz zapsany nejaky port s protokolem, tak se musi pokracovat ve formatu or ...
            if (!str.empty())
                str = str + " or (tcp and port" + port;
            else
                str = str + "(tcp and port" + port;
        }
        else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0)
        {
            parameters = false;
            if (!str.empty())
                str = str + " or (udp and port" + port;
            else
                str = str + "(udp and port" + port;
        }
        else if (strcmp(argv[i], "--arp") == 0)
        {
            // arp a icmp nema svuj port
            parameters = false;
            if (!str.empty())
                str = str + " or (arp)";
            else
                str = str + "(arp)";
        }
        else if (strcmp(argv[i], "--icmp") == 0)
        {
            parameters = false;
            if (!str.empty())
                str = str + " or (icmp)";
            else
                str = str + "(icmp)";
        }
        else if (strcmp(argv[i], "-n") == 0)
        {
            // pres parametr vraceni nalazene -n hondoty
            i++;
            *n = atoi(argv[i]);
        }
    }
    // filtr parametru funguje s tvarem ([protocol] and port(range) [number|range]) or ...
    // pro arp a icmp bez portu ve tvaru ([protocol]) or ...
    // tento vytvoreny string dale pouziva funkce pcap_compile, ktera jej spracuje do parametru filter
    // filter dal predava do pcap_setfilter
    if (parameters)
        str = "(tcp and port" + port + " or (udp and port" + port + " or (arp) or (icmp)";
    // vraceni vysledneho stringu filteru
    return str;
}

// funkce pro vypis obsahuje nalezene packety
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    const u_char *ch;
    // vypsani offsetu
    printf("0x%04x  ", offset);
    /* hex */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", *ch);
        ch++;
    }
    printf(" ");
    // funckce isprint() kontroluje, jestli je znak tisknutelny, jinak tiskne "."
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
    return;
}

void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *ch = payload;
    //kdyz rovnou data jsou mensich nez 16 bitu
    if (len <= line_width)
    {
        print_hex_ascii_line(ch, len, offset);
        return;
    }
    //vice radku
    while (true)
    {
        // delka jednoho radku
        // v prvnich kroku spracuje jen 16 bitu a offset se nastavi na 16
        //zustava  vic jak 30 bitu a podle toho delku radku
        line_len = line_width % len_rem;
        // vypisu radek
        // offset je posun
        print_hex_ascii_line(ch, line_len, offset);
        // len_rem kolik zustava bitu do konce
        len_rem = len_rem - line_len;
        // v prvnich kroku spracuje dalsich 16 bitu a offset se nastavi na 32
        //ch je pointer co ukazuje na zacatek bitu, ktere se maji vypsat
        ch = ch + line_len;
        offset = offset + line_width;
        if (len_rem <= line_width)
        {
            //delka je mensi nez 16, offset je 48 bitu
            //vypis poslednich bitu
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    return;
}

void print_time(const struct pcap_pkthdr *header)
{
    struct tm ts;
    char buf[80];
    // cas ve tvaru "ddd yyyy-mm-dd hh:mm:ss zzz"
    ts = *localtime(&(header->ts.tv_sec));
    strftime(buf, sizeof(buf), "timestamp: %Y-%m-%dT%H:%M:%S", &ts);
    printf("%s.%ld\n", buf, (header->ts.tv_usec/1000));
    printf("frame length: %d bytes\n", header->len);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // vypsani casu
    print_time(header);

    static int count = 1; /* packet counter */
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet; /* The ethernet header [1] */
    const struct ip6_hdr *ip6;             /* The IP header */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const struct sniff_udp *udp;
    // const u_char *payload; /* Packet payload */
    int size_ip;
    // int size_payload;
    count++;
    /* define ethernet header */

    ethernet = (struct sniff_ethernet *)(packet);

    // vypsani MAC adres s oddelovacem ":"
    printf("src MAC: ");
    for (int j = 0; j < 6; j++)
    {
        if (j != 0)
            printf(":");
        // %02x vypise adresu ve tvaru hexadecimalniho cisla
        printf("%02x", ethernet->ether_shost[j]);
    }
    printf("\ndst MAC: ");
    for (int j = 0; j < 6; j++)
    {
        if (j != 0)
            printf(":");
        printf("%02x", ethernet->ether_dhost[j]);
    }
    printf("\n");

    // ARP nema v sobe IP adresu
    if (ntohs(ethernet->ether_type) != 0x0806)
    {
        if (ntohs(ethernet->ether_type) == 0x0800) // Ipv4
        {
            ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
            size_ip = IP_HL(ip) * 4;
            // vypsani vysledne ip adresy
            printf("src IP: %s\n", inet_ntoa(ip->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip->ip_dst));
            if (ip->ip_p == IPPROTO_TCP) // pro TCP a UDP
            {
                tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
                printf("src port: %d\n", ntohs(tcp->th_sport));
                printf("dst port: %d\n\n", ntohs(tcp->th_dport));
            }
            else if (ip->ip_p == IPPROTO_UDP)
            {
                udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
                printf("src port: %d\n", ntohs(udp->uh_sport));
                printf("dst port: %d\n\n", ntohs(udp->uh_dport));
            }
        }
        else if (ntohs(ethernet->ether_type) == 0x68DD) // IPv6
        {
            ip6 = (struct ip6_hdr *)(packet + SIZE_ETHERNET);

            char buffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &ip6->ip6_src, buffer, INET6_ADDRSTRLEN);
            printf("src IP: %s\n", buffer);
            inet_ntop(AF_INET6, &ip6->ip6_src, buffer, INET6_ADDRSTRLEN);
            printf("dst IP: %s\n", buffer);
            if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP) // pro TCP a UDP
            {
                // delka hlavicky je vzdy 40
                tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + 40);
                printf("src port: %d\n", ntohs(tcp->th_sport));
                printf("dst port: %d\n\n", ntohs(tcp->th_dport));
            }
            else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP)
            {
                udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + 40);
                printf("src port: %d\n", ntohs(udp->uh_sport));
                printf("dst port: %d\n\n", ntohs(udp->uh_dport));
            }
        }
    }

    print_payload(packet, header->len);
    return;
}

// pokud uzivatel zada samotne -i, nebo nezada vubec, vytiskne se list moznych pouzitelnych rozhrani
void print_interface(pcap_if_t *alldevs)
{
    // v alldevs jsou zarizeni
    for (pcap_if_t *d = alldevs; d; d = d->next)
    {
        printf("%s", d->name);
        printf("\n");
    }
    exit(0);
}

// kontrola zadani argumentu [-i|--interface]
char *check_interface(int argc, char **argv, pcap_if_t *alldevs)
{
    // pomocna promenna,jestli byl argument -i zadan
    bool interface = false;
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0)
        {
            interface = true;
            // tiskne seznam vsech moznych rozhrani pokud prikazova radka konci -i
            if ((i + 1) != (int)argc)
            {
                i++;
                // nebo -i -jinyParametr
                if (strstr(argv[i], "-") != NULL)
                {
                    print_interface(alldevs);
                }
                else
                {
                    // vraci jmeno jako druhy argument po [-i|--interface]
                    char *s = argv[i];
                    return s;
                }
            }
            else
            {
                print_interface(alldevs);
            }
        }
    }
    // nebo neni zadan vubec
    if (!interface)
        print_interface(alldevs);
    char *s = argv[0];
        return s;
}

int main(int argc, char **argv)
{
    print_help(argc, argv);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program filter; /* to hold compiled program */
    bpf_u_int32 pMask;         /* subnet mask */
    bpf_u_int32 pNet;          /* ip address*/
    pcap_if_t *alldevs;

    // dafaultni hodnota pokud neni zadany parametr -n
    int n = 1;
    // zajisti seznam pouzitelnych zarizeni
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        exit(1);
    }
    // kontrola [-i|--interface]
    char *dev = check_interface(argc, argv, alldevs);
    // string filteru
    string strFilter = check_arg(argc, argv, &n);

    // zajisti cislo IPv4
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    // umozni zahajeni zachytavani paket v siti
    // vraci string kdyz najde device, kterou je treba otevrit
    descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
    if (descr == NULL)
        exit(1);
    // konvertuje string do filtru protokolu filter
    cout << strFilter <<endl;
    if (pcap_compile(descr, &filter, strFilter.c_str(), 0, pNet) == -1)
        exit(1);
    // pouzije filtr filter, ktery dostane a zpracuje ho
    if (pcap_setfilter(descr, &filter) == -1)
        exit(1);
    // pro n pocet packet se vypise n packet
    pcap_loop(descr, n, got_packet, NULL);
}