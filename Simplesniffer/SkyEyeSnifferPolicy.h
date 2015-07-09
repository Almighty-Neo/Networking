#include "SkyEyePublicHeader.h"
#ifndef COMDEF_H_POLICY
#define COMDEF_H_POLICY

#define MAXKEYWORDS 10

// marks define
#define MARK_ARRAY_COUNT 10
#define MARK_COUNT 20

struct policy_list{
	u_int ether_check_dhost;	//Check or not destination Mac Address
	u_int ether_check_shost;	//Check or not source Mac Address
	char ether_dhost[6];		//Destination Mac Address 
	char ether_shost[6];		//Source Mac Address
	u_short ether_type;			//Ethern Type: ARP, RARP, IP

	u_long ip_source;			//Source IP Address
	u_long ip_destination;		//Destination IP Address
	u_long ip_source_mask;
	u_long ip_destination_mask;

	u_short proto_type;			//Protocal Type: UDP, TCP
	u_short sport;				//Source Port
	u_short dport;				//Destination Port

	u_char keywords[MAXKEYWORDS][32];//keyword array which turned from keyword string
	u_int  keywordslen[MAXKEYWORDS];
	u_char keyword[256];			//origin keyword string, split keyword by mark '|'

	u_int  mark_position[MARK_COUNT][MARK_ARRAY_COUNT];   //mark postion array
	u_int  mark_array_count [MARK_COUNT];
	u_char mark_array[MARK_COUNT][MARK_ARRAY_COUNT];      //mark array

	int keywords_count;
	int marks_count;

	struct policy_list * pNext;
};



int transfer_keyword(const u_char * strKeyword, int lenth);

int check_keywords(const u_char * strPackage, int length);

int find_mark(const u_char *payload, int len);

void define_mark();

char * get_keyword(int number);

int policy_test();


struct policy_list * policy_add(char * mac_source,
			   char * mac_destination,
			   char * ip_source, 
			   char * ip_destination, 
			   char * ip_source_mask,
			   char * ip_destination_mask,
			   int ethern_protocal,
			   int protocal,
			   long port_source,
			   long port_destination,
			   char * keyword_string,
			   char * mark_string);

int policy_del(struct policy_list * des);

int policy_clear();


#endif