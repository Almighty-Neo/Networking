 
#include "SkyEyePublicHeader.h"
#include "SkyEyeSnifferClient.h"
#include "SkyEyeSnifferPolicy.h"

/*function implement start*/

extern struct policy_list;

extern struct policy_list * policy_list_head;
extern struct policy_list * policy_list_tail;



/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
 
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
 
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
		printf("   ");
		}
	}
	printf("   ");
 
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
		printf("%c", *ch);
		else
		printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

 int len_rem = len;
 int line_width = 16;   /* number of bytes per line */
 int line_len;
 int offset = 0;     /* zero-based offset counter */
 const u_char *ch = payload;

 if (len <= 0)
  return;
    
 /* data fits on one line */
 if (len <= line_width) {
  print_hex_ascii_line(ch, len, offset);
  return;
 }

 /* data spans multiple lines */
 for ( ;; ) {
  /* compute current line length */
  line_len = line_width % len_rem;
  /* print line */
  print_hex_ascii_line(ch, line_len, offset);
  /* compute total remaining */
  len_rem = len_rem - line_len;
  /* shift pointer to remaining bytes to print */
  ch = ch + line_len;
  /* add offset */
  offset = offset + line_width;
  /* check if we have line width chars or less */
  if (len_rem <= line_width) {
   /* print last line and get out */
   print_hex_ascii_line(ch, len_rem, offset);
   break;
  }
 }

return;
}

void process_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	int i = 0, *counter = (int *)arg;
	const struct db_ip *ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;
	//int pointer_offset = 0;
	//u_char *pointer_str;

    /* jump pass the ethernet header */
    ip = (struct db_ip *)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct db_ip))
    {
        printf("truncated ip %d\n", length);
        return;
    }
    len = ntohs(ip->ip_len);
    hlen = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */
    /* check version */
    if (version != 4 && version != 6)
    {
        //fprintf(stdout, "Unknown version %d\n", version);
        return;
    }
    /* check header length */
    if (hlen < 5 )
    {
        //fprintf(stdout, "bad-hlen %d \n", hlen);
    }
    /* see if we have as much packet as we should */
    if (length < len)
		;
    //    printf("\ntruncated IP - %d bytes missing\n", len - length);
    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);

    /* Print details of packets only from 192.168.42.5*/
    if (!strcmp(inet_ntoa(ip->ip_src), "192.168.42.8"))
    {


		if(ip->ip_p == 6 || 1) // TCP protocal
		{


			int tcp_offset = sizeof(struct ether_header)
				+ sizeof(struct db_ip);
			struct db_tcp * tcp = (struct db_tcp*)(packet + tcp_offset);
			int tcppacket_offset = tcp_offset + TH_OFF(tcp)*4;

			if(1 && 0 == check_keywords(
				packet + tcppacket_offset, 
				pkthdr->len - TH_OFF(tcp)*4)
				)
				return;

			// To AHUT student information system
/*
			printf("Username:");
			get_string(packet + tcppacket_offset + pointer_offset + 8, 
				length - tcppacket_offset - pointer_offset, 
				'&');
			pointer_offset = find_string(
				packet + tcppacket_offset, 
				"TextBox2", 
				length - tcppacket_offset,
				8);
			printf("	Password:");
			get_string(packet + tcppacket_offset + pointer_offset + 8, 
				length - tcppacket_offset - pointer_offset, 
				'&');
			printf("\n");

*/			/* print SOURCE and DESTINATION IPs*/
//			/
			printf("Source IP: %s:%d ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			printf(" Destination IP: %s:%d \n",inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			printf("Protocal: %d\n", ip->ip_p);
			printf("Packet Count: %d\n", ++(*counter));
			printf("Received Packet Size:%d / %d\n", tcppacket_offset, pkthdr->len);
			printf("Payload:\n");
			
			print_payload(packet + tcppacket_offset, pkthdr->len - TH_OFF(tcp)*4);
			/*
			for (i = tcppacket_offset; i < pkthdr->len; i++) {
					if (isprint(packet[i]))
							printf("%c ", packet[i]);
					else 
							printf(". ");

					if ((i % 48 == 0 && i != 0) || i == pkthdr->len-1)
							printf("\n");
							
			}*/
		}

    }
        return;
}

int main() {
	char keyword_string[1024] = {0};
	int count = 0;
	pcap_t *descr = NULL;
	char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	strcpy(errbuf, "1\0");

	load_database();
	//ip_add = inet_addr("192.168.42.5");

	/* Get the name of the first device suitable for capture */
	sprintf(keyword_string, "954015636|414430547|15905553384");
	transfer_keyword(keyword_string, strlen(keyword_string) + 1);
    define_mark();

	device = pcap_lookupdev(errbuf);
	printf("Find net device: %s\n", device);



	/* Open device in promiscuous mode */
	descr = pcap_open_live("wlan0", MAXBYTE2CAPTURE, 1, 512, errbuf);
	printf("Wlan listening begining.\n");
	/* Loop forever & call process_packet() for every received packet */
	pcap_loop(descr, -1, got_ethernet_packet, (u_char *)&count);

	return 0;
}

int 
got_data_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet,int size_header, struct header_info * inf, const struct policy_list * plc)
{
	const u_char *payload;                    /* Packet payload */ 
	int size_payload;
  
	/* define/compute  payload (segment) offset */
	payload = (u_char *)(packet + size_header);
 
	/* compute tcp payload (segment) size */
	const struct db_ip *ip;
	ip = (struct db_ip*)(packet + SIZE_ETHERNET);
	size_payload = ntohs(ip->ip_len) - (size_header-SIZE_ETHERNET);//data len=total len-size_ip-size_tcp
 
	/*
	* Print payload data; it might be binary, so don't just
	* treat it as a string.
	*/

	// Check Key Words
	int keyword_mark = policy_check_keywords(
		payload, 
		size_payload,
		plc
		);

	if(1 && 0 == keyword_mark)
		return 0;
	//else
		//strcpy(inf->keyword, get_keyword(keyword_mark - 1));

	if (size_payload > 0 && (1 || find_mark(payload, size_payload) != -1)) {
		inf->payload = payload;
		inf->payload_length = size_payload;

		printf("Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
        return 1;
	}
	return 0;
}

int 
got_udp_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet,int size_ip, struct header_info * inf, const struct policy_list * plc)
{
	struct db_udp *udp;
	int  size_udp;
	int  ret = 0;
	u_short sport;
	u_short dport;
	u_short length;
	udp=(struct db_udp*)(packet+size_ip);
	sport=ntohs(udp->udp_source_port);
	dport=ntohs(udp->udp_destination_port);
	length=ntohs(udp->udp_length);

 
	if((plc->sport == 0 || sport == plc->sport) && (plc->dport == 0 || dport == plc->dport))
		ret = got_data_package(args,header,packet,size_udp,inf,plc);

	if(ret){
		printf("-------UDP Protocol (Transport Layer)---------\n");
		printf("Source Port:%d\n",sport);
		printf("Destination Port:%d\n",dport);
		printf("Length:%d\n",length);
		printf("Checksum:%d\n",ntohs(udp->udp_checksum));
		size_udp = length + size_ip;
	}
	return ret;
}

/*
 * dissect/print tcp packet
 */
int 
got_tcp_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet,int size_ip, struct header_info * inf, const struct policy_list * plc)
{ 
	const struct db_tcp *tcp;            /* The TCP header */
	int size_tcp; 
	int  ret = 0;

	u_char flags;
	u_short windows;
	u_short urgent_pointer;
	u_int sequence;
	u_int acknowledgement;
	u_int16_t checksum;
	u_short sport;
	u_short dport;
 
	/* define/compute tcp header offset */
	tcp = (struct db_tcp*)(packet + size_ip);
	size_tcp = TH_OFF(tcp)*4;

	if (size_tcp < 20) {
		printf(" * Invalid TCP header length: %u bytes\n", size_tcp);
		return ret;
	}
	sequence=ntohl(tcp->th_seq);
	acknowledgement=ntohl(tcp->th_ack);
	windows=ntohs(tcp->th_win);
	urgent_pointer=ntohs(tcp->th_urp);
	flags=tcp->th_flags;
	checksum=ntohs(tcp->th_sum);
	sport=ntohs(tcp->th_sport);
	dport=ntohs(tcp->th_dport);


	size_tcp=size_tcp+size_ip;
	/* Set relative information */
	inf->original_port = sport;
	inf->destination_port = dport;

	if((plc->sport == 0 || sport == plc->sport) && (plc->dport == 0 || dport == plc->dport))
		ret = got_data_package(args,header,packet,size_tcp,inf,plc);
  

	if(ret){
		printf("-------TCP Protocol (Transport Layer)---------\n");
		printf("   Src port: %d\n", sport);
		printf("   Dst port: %d\n", dport);
		printf("Sequence Number:%u\n Acknowledgement Number:%u\n Header Length:%d\n Reserved:%d\n",sequence,acknowledgement,size_tcp,tcp->th_offx2);
		printf("Flags:");
		if(flags & 0x08) printf("PSH");
		if(flags & 0x10) printf("ACK");
		if(flags & 0x02) printf("SYN");
		if(flags & 0x20) printf("URG");
		if(flags & 0x01) printf("FIN");
		if(flags & 0x04) printf("RST");
		printf("\n");
		printf("Window Size:%d\n",windows);
		printf("Checksum:%d\n",checksum);
		printf("Urgent Pointer:%d\n",urgent_pointer);
	}
	return ret;
}

/*
 * dissect/print ip packet
 */
int 
got_ip_package(u_char *args,const struct pcap_pkthdr *header,const u_char *packet, struct header_info * inf, const struct policy_list * plc)
{
	const struct db_ip *ip;              /* The IP header */
	int size_ip;
	int  ret = 0;

	u_int offset;
	u_char tos;
	u_int16_t checksum;
       
	/* define/compute ip header offset */
	ip = (struct db_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("*Invalid IP header length: %u bytes\n", size_ip);
		return ret;
	}
	checksum=ntohs(ip->ip_sum);
	tos=ip->ip_tos;
	offset=ntohs(ip->ip_off);

	//if (1 && strcmp(inet_ntoa(ip->ip_src), "192.168.42.8"))
 //   {
	//	return ret;
	//}

	/* print source and destination IP addresses */
	strcpy(inf->original_ip, inet_ntoa(ip->ip_src));
	strcpy(inf->destination_ip, inet_ntoa(ip->ip_dst));
	inf->protocal = ip->ip_p;

	/* determine protocol */ 
	size_ip=size_ip+SIZE_ETHERNET;
	//printf("IP Header Checking..\n");
	/* Compare Packet Information to Policy */
	if(((ip->ip_src.s_addr & plc->ip_source_mask) == (plc->ip_source_mask & plc->ip_source)) &&
		((ip->ip_dst.s_addr & plc->ip_destination_mask) == (plc->ip_destination_mask & plc->ip_destination)) && 
		(plc->proto_type == 0 || plc->proto_type == ip->ip_p)
		)
	{
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				ret = got_tcp_package(args,header,packet,size_ip,inf,plc);
				break;
			case IPPROTO_UDP: 
				ret = got_udp_package(args,header,packet,size_ip,inf,plc);
				break;
			default:
				printf("   Protocol: unknown\n");
				break;
		}
	}

	if(ret){
		printf("-------IP Protocol (Network Layer)---------\n");
		printf("IP Version:%d\n",IP_V(ip));
		printf("Header Length:%d\n",size_ip);
		printf("TOS:%d\n",tos);
		printf("Total length:%d\n",ntohs(ip->ip_len));
		printf("Identification:%d\n",ntohs(ip->ip_id));
		printf("Offset:%d\n",(offset & 0x1fff)*8);
		printf("TTL:%d\n",ip->ip_ttl);
		printf("Header checksum:%d\n",checksum);
		printf(" From: %s", inet_ntoa(ip->ip_src));
		printf("  To: %s\n", inet_ntoa(ip->ip_dst));
		/* Insert Information to Database*/
		/*
		insert_information_test_string(
			inf->original_ip, 
			inf->destination_ip, 
			inf->original_port, 
			inf->destination_port, 
			inf->keyword,
			inf->payload,
			inf->payload_length);
			*/
	}

	return ret;
}

/*
 * dissect/print ethernet packet
 */
void
got_ethernet_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	struct policy_list * pEnum = policy_list_head;	/* policy list */
	struct header_info inf;				/* The Information */


	/* declare pointers to packet headers */
	const struct db_ethernet *ethernet;  /* The ethernet header [1] */
		u_short ethernet_type;
		u_char *mac_string;

	//printf("================The %d package is captured.======================\n",count);
	count++;

	//	printf("-------Ethernet Protocol (Link Layer)---------\n");
	/* get ethernet header */    
	ethernet = (struct db_ethernet*)(packet);
	/*
	//printf("Mac Source Address is:\n"); 
	//mac_string=(u_char*)ethernet->ether_shost;
	//printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	//printf("Mac Destination Address is:\n");
	//mac_string=(u_char*)ethernet->ether_dhost;
	//printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
	ethernet_type=ntohs(ethernet ->ether_type);
	switch(ethernet_type)
	{
		case 0x0800: got_ip_package(args,header,packet);break;
		//case 0x0806: printf("The network layer is ARP protocol\n");break;
		//case 0x0835: printf("The network layer is RARP protocol\n");break;
		default:break;
	}
	*/

	memcpy(inf.destination_mac, ethernet->ether_dhost, 6);		//set mac address
	memcpy(inf.original_mac, ethernet->ether_shost, 6);
	int check_sign = 0;	//if 0 dont go to next step
	while(pEnum != 0)
	{
		check_sign = 1;
		if(pEnum->ether_check_shost != 0)
			if(memcmp(ethernet->ether_shost, pEnum->ether_shost, 6))	//if dont same
				check_sign = 0;
		if(pEnum->ether_check_dhost != 0)
			if(memcmp(ethernet->ether_dhost, pEnum->ether_dhost, 6))	//if dont same
				check_sign = 0;
		ethernet_type=ntohs(ethernet ->ether_type);
		if(ethernet_type != pEnum->ether_type)
			check_sign = 0;
		if(check_sign != 0)
			got_ip_package(args,header,packet,&inf,pEnum);

		pEnum = pEnum->pNext;
	}
return;
}


