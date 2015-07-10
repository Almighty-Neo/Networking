#include "SkyEyePublicHeader.h"
#include "SkyEyeSnifferPolicy.h"

unsigned long ip_add = 0;
extern struct policy_list;

u_char targetip[16] = {0};			//target ip adress, which you want to listen
u_char keywords[MAXKEYWORDS][32] = {{0}};//keyword array which turned from keyword string
u_int  keywordslen[MAXKEYWORDS] = {0};
u_char keyword[256] = {0};			//origin keyword string, split keyword by mark '|'

u_int  mark_position[MARK_COUNT][MARK_ARRAY_COUNT] = {{0}};   //mark postion array
u_int  mark_array_count [MARK_COUNT] = {0};
u_char mark_array[MARK_COUNT][MARK_ARRAY_COUNT] = {{0}};      //mark array

int countKeyword = 0;				//count of keywords
int mark_count = 0;


struct policy_list * policy_list_head = 0;
struct policy_list * policy_list_tail = 0;


/*
 * set marks and detail inforamtion
 */
void define_mark()
{
    mark_position[0][0] = 4; mark_array[0][0] = 0x00;
    mark_position[0][1] = 5; mark_array[0][1] = 0x10;
    mark_position[0][2] = 6; mark_array[0][2] = 0x00;
    mark_position[0][3] = 7; mark_array[0][3] = 0x01;
    mark_array_count[0] = 4;
    
    mark_count = 1;

	policy_test();
}

/*
 * judge whether or not marks in payload
 * if yes return >=0
 * if no return -1
 */
int find_mark(const u_char *payload, int len)
{
    int i = 0;
    int n = 0;
    for(i = 0; i < mark_count; i++)
    {
        for (n = 0; n < mark_array_count[i]; n++){
            if(mark_position[i][n] >= len ||
               *(payload + mark_position[i][n]) != mark_array[i][n])
                break;
        }
                if(n == mark_array_count[i])
            return i;
    }

    return -1;
}

int last(const u_char *p, u_char c) { //找到c在p中最后匹配的位置,没有就返回－1
    int length = strlen((char *)p), count  = 0;
    u_char *pp = (u_char *)p + length -1;
    while (pp >= p)
    {
        if (*pp == c)
        {
            return length - count - 1;
        }
        pp--;
        count++;
    }
    return -1;
}

int min(int a, int b){
    return (a <= b) ? a : b;
}

int find_string(const u_char *T,const u_char *p, int lenT, int lenP) {
    int n = lenT;
    int m = lenP; //strlen(p);
    int i = m-1, j = m-1;
    while (i <= n-1)
    {
        if (T[i]==p[j])
        {
            if (j==0)
            {
                return i;
            }
            else
                i--, j--;
        }
        else {
            i = i + m - min(j, 1+last(p, T[i]) ); //往后跳，取决于最后一次匹配的字符的位置
            j = m - 1;
        }
    }
    return -1;
}

/*
 * transfer string to keywords
 * always return 0
 */
int transfer_keyword(const u_char * strKeyword, int lenth)
{
	int n = 0;
	int k = 0;
	int i = 0;
	for(i = 0; i < lenth; i++)
	{
		if(*(strKeyword + i) != '|' && *(strKeyword + i) != 0)
			keywords[n][k++] = *(strKeyword + i);
		else
		{
			keywords[n][k++] = '\0';
			keywordslen[n] = k - 1;
			k = 0;
			n++;
			if(n > MAXKEYWORDS)
				return -2;			//out of count
		}
	}
	countKeyword = n;
	//printf("Count: %d\n", n);
	//for(i = 0; i < n; i++)
	//{
	//	printf("%s\n", keywords[i]);
	//}
	return 0;
}

/*
 * check keywords in string
 * if yes return a number which is number of keywords + 1
 * else return 0
 */
int check_keywords(const u_char * strPackage, int length)
{
	int i = 0;
	int pointer_offset = 0;
	for(i = 0; i < countKeyword; i++)
	{
		if(-1 == (pointer_offset = find_string(
			strPackage, 
			keywords[i], 
			length,
			keywordslen[i])))
			continue;
		else
		{
			printf("Detect Keyword: %s\n", keywords[i]);
			return 1 + i;
		}
		
	}
	return 0;
}

int get_string(u_char * targt, int len, u_char end_sg)
{
	int i = 0;
	for(i = 0; i < len && *(targt + i) != end_sg; i++)
	{
		printf("%c", *(targt + i));
	}
	return 0;
}

char * get_keyword(int number)
{
	return keywords[number];
}

/* ---------- Policy Management  ----------- */
int policy_test()
{
	char mac_address[20] = {"00:00:00:00:00:00"};
	//char * mac_string = mac_address;
	//printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));

	policy_add(
		mac_address, 
		"00:00:00:00:00:00", 
		"115.28.4.146", 
		"128.0.0.1", 
		"0.0.0.0", 
		"0.0.0.0",
		0x0800,
		IPPROTO_TCP,
		21,
		0,
		"",
		"mark"
		);
		policy_add(
		mac_address, 
		"00:00:00:00:00:00", 
		"115.28.4.146", 
		"128.0.0.1", 
		"0.0.0.0", 
		"0.0.0.0",
		0x0800,
		IPPROTO_TCP,
		0,
		21,
		"",
		"mark"
		);
	return 0;
}

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
			   char * mark_string)
{
	char mac_address[7] = {0};
	struct policy_list * plc =(struct policy_list *) malloc(sizeof (struct policy_list));
	struct policy_list * pEnum = policy_list_head;
	int i = 0;
	if(plc == 0)
	{
		printf("Memory Allocate Error, Add Policy Failed.\n");
		return 0;
	}

	memset(plc, 0, sizeof (struct policy_list));

	sscanf(mac_destination, "%02x:%02x:%02x:%02x:%02x:%02x", 
		&mac_address[0],
		&mac_address[1],
		&mac_address[2],
		&mac_address[3],
		&mac_address[4],
		&mac_address[5]
	);
	memcpy(plc->ether_dhost, mac_address, 6);
	plc->ether_check_dhost = 0;
	for(i = 0; i < 6; i++)
		plc->ether_check_dhost += *(mac_address + i);

	sscanf(mac_source, "%02x:%02x:%02x:%02x:%02x:%02x", 
		&mac_address[0],
		&mac_address[1],
		&mac_address[2],
		&mac_address[3],
		&mac_address[4],
		&mac_address[5]
	);
	memcpy(plc->ether_shost, mac_address, 6);
	plc->ether_check_shost = 0;
	for(i = 0; i < 6; i++)
		plc->ether_check_shost += *(mac_address + i);


	plc->ether_type		= ethern_protocal;

	plc->ip_source		= inet_addr(ip_source);
	plc->ip_destination	= inet_addr(ip_destination);

	plc->ip_source_mask		= inet_addr(ip_source_mask);
	plc->ip_destination_mask= inet_addr(ip_destination_mask);

	plc->proto_type		= protocal;
	plc->sport			= port_source;
	plc->dport			= port_destination;

	plc->pNext			= 0;

	/* ---- Keywords and Marks Add ---- */

	policy_transfer_keyword(keyword_string, strlen(keyword_string) + 1, plc);
	/* ---- Keywords and Marks End ---- */
	if(policy_list_head == 0)
	{
		policy_list_head = plc;
	}
	else
	{
		pEnum = policy_list_head;
		while(pEnum->pNext != 0)
			pEnum = pEnum->pNext;
		pEnum->pNext = plc;
	}
	printf("Item add!\n");

	return plc;
}

int policy_del(struct policy_list * des)
{
	struct policy_list * pEnum = policy_list_head;
	struct policy_list * pBuf;
	if(policy_list_head == 0)
	{
		// null list
		return 0;
	}
	else
	{
		pEnum = policy_list_head;
		pBuf = pEnum;

		while(pEnum != 0)
		{
			if(pEnum == des)
			{
				if(pBuf == policy_list_head)
					policy_list_head = des->pNext;
				else
					pBuf->pNext = des->pNext;

				free(des);		// Release Memory
				printf("Item delete!\n");
				break;
			}
			pBuf = pEnum;
			pEnum = pEnum->pNext;
		}
		
	}
	return 1;
}

int policy_clear()
{
	if(policy_list_head == 0)
	{
		// null list
		return 0;
	}
	while(policy_list_head != 0)
		policy_del(policy_list_head);
	
	return 1;
}

int policy_transfer_keyword(const u_char * strKeyword, int lenth, struct policy_list * plc)
{
	int n = 0;
	int k = 0;
	int i = 0;
	if(strlen(strKeyword) == 0)
	{
		plc->keywords_count = 0;
		return 0;
	}
	for(i = 0; i < lenth; i++)
	{
		if(*(strKeyword + i) != '|' && *(strKeyword + i) != 0)
			plc->keywords[n][k++] = *(strKeyword + i);
		else
		{
			plc->keywords[n][k++] = '\0';
			plc->keywordslen[n] = k - 1;
			k = 0;
			n++;
			if(n > MAXKEYWORDS)
				return -2;			//out of count
		}
	}
	plc->keywords_count = n;
	printf("Count: %d\n", n);
	//for(i = 0; i < n; i++)
	//{
	//	printf("%s\n", keywords[i]);
	//}
	return 0;
}

int policy_transfer_fingerprint(const u_char * strKeyword, struct policy_list * plc)
{

}

int policy_check_keywords(const u_char * strPackage, int length, struct policy_list * plc)
{
	int i = 0;
	int pointer_offset = 0;
	if(plc->keywords_count == 0)
		return 1;
	printf("Check Keywords\n");
	for(i = 0; i < plc->keywords_count; i++)
	{
		if(-1 == (pointer_offset = find_string(
			strPackage, 
			plc->keywords[i], 
			length,
			plc->keywordslen[i])))
			continue;
		else
		{
			printf("Detect Keyword: %s\n", plc->keywords[i]);
			return 1 + i;
		}
		
	}
	return 0;
}

int policy_check_fingerprint(const u_char *payload, int len, struct policy_list * plc)
{
    int i = 0;
    int n = 0;

    for (n = 0; n < plc->mark_array_count; n++){
        if(plc->mark_position[n] >= len ||
            *(payload + plc->mark_position[n]) != plc->mark_array[n])
            break;
    }
            if(n == plc->mark_array_count)
        return i;

    return -1;
}

/* ----------------------------------------- */