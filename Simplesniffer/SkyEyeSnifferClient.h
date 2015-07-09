#include "SkyEyePublicHeader.h"
#include "SkyEyeSnifferPolicy.h"

#define MAXBYTE2CAPTURE 4096


/*protocol define start*/
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct db_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct db_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct db_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header */
struct db_udp//udp protocol
{
 u_int16_t udp_source_port;
 u_int16_t udp_destination_port;
 u_int16_t udp_length;
 u_int16_t udp_checksum;
};

/*
IP Header
*/

struct tcphdr
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
	# if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
# elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
# else
#   error "Adjust your <bits/endian.h> defines"
# endif
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};

struct header_info
{
	char destination_mac[6];
	char original_mac[6];
	char keyword[48];
	char original_ip[20];
	char destination_ip[20];
	long original_port;
	long destination_port;
	char * payload;
	long payload_length;
	int protocal;
};


/* function define start */

void
got_ethernet_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int 
got_ip_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet, struct header_info * inf, const struct policy_list * plc);

int 
got_tcp_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet,int size_ip, struct header_info * inf, const struct policy_list * plc);

int 
got_udp_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet,int size_ip, struct header_info * inf, const struct policy_list * plc);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

int 
got_data_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet,int size_header, struct header_info * inf, const struct policy_list * plc);

extern int load_database();

extern int insert_information_test(char * orgIP, char * desIP, int orgPort, int desPort,  char * package, int length);

extern int insert_information_test_string(char * orgIP, char * desIP, int orgPort, int desPort, char * keyword, char * package, int length);

extern int transfer_keyword(const u_char * strKeyword, int lenth);

extern int check_keywords(const u_char * strPackage, int length);

extern int find_mark(const u_char *payload, int len);

extern void define_mark();

extern char * get_keyword(int number);
/*function define end*/
