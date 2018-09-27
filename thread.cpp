#include "thread.h"
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

    typedef struct ip_address{
        u_char byte1;
        u_char byte2;
        u_char byte3;
        u_char byte4;
    }ip_address;
    /* Ethernet header */
    struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };

    /* IP header */
    struct sniff_ip {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* dont fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        ip_address ip_src,ip_dst; /* source and dest address */
    };
    #define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)		(((ip)->ip_vhl) >> 4)

    /* TCP header */
    typedef u_int tcp_seq;

    struct sniff_tcp {
        u_short th_sport;	/* source port */
        u_short th_dport;	/* destination port */
        tcp_seq th_seq;		/* sequence number */
        tcp_seq th_ack;		/* acknowledgement number */
        u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;		/* window */
        u_short th_sum;		/* checksum */
        u_short th_urp;		/* urgent pointer */
};
char err[PCAP_ERRBUF_SIZE+1];

Thread::Thread(QString interface)
{
    this->interface=interface;
}

Thread::Thread()
{

}

void Thread::run()
{
    pcap_t *handle = pcap_open_live(interface.toLatin1().data(), BUFSIZ, 1, 1000, err);
    if (handle == NULL) {
        emit error("Interface \"" + interface + "\" could not be read.");
    }else{
        struct pcap_pkthdr header;
        const u_char *packet;
        const struct sniff_ethernet *ethernet; /* The ethernet header */
        const struct sniff_ip *ip; /* The IP header */
        const struct sniff_tcp *tcp; /* The TCP header */
        const u_char *payload; /* Packet payload */
        u_int size_ip;
        u_int size_tcp;
        /* Grab a packet */
        while(1){
            packet = pcap_next(handle, &header);
            ethernet = (struct sniff_ethernet*)(packet);
            ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
            size_ip = IP_HL(ip)*4;
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            QString stuff= QString::fromUtf8((char *)payload);
            QString type;
            if(stuff.contains("GET"))
            {
                type="(GET)";
            }
            else if(stuff.contains("HTTP") || stuff.contains("OK"))
            {
                type="(HTTP)";
            }
            QString source = QString::number((int)ip->ip_src.byte1) + "." + QString::number((int)ip->ip_src.byte2) + "." + QString::number((int)ip->ip_src.byte3) + "." + QString::number((int)ip->ip_src.byte4) + ":" + QString::number((int)tcp->th_sport);
            QString dest = QString::number((int)ip->ip_dst.byte1) + "." + QString::number((int)ip->ip_dst.byte2) + "." + QString::number((int)ip->ip_dst.byte3) + "." + QString::number((int)ip->ip_dst.byte4)  + ":" + QString::number((int)tcp->th_dport);
            if(dest.length() < 10)
            {
                dest.append("\t");
            }
            QString head = type + "\t" + source + "\t--->\t" + dest;
            if(((int)ip->ip_p) == 6){
                head.append("\t(TCP)");
            }else if(((int)ip->ip_p) == 17){
                head.append("\t(UDP)");
            }else if(((int)ip->ip_p) == 2){
                head.append("\t(IGMP)");
            }else if(((int)ip->ip_p) == 87){
                head.append("\t(TCF)");
            }else{
                head.append("\t" + QString::number((int)ip->ip_p));
            }
            int i;
            for(i = 0; i<stuff.length(); i++){
                if(stuff.at(i).unicode() > 127)
                    break;
            }
            emit captured(stuff.mid(0, i), head);
        }
    }
}
