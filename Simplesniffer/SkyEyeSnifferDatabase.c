#include <mysql/mysql.h>
#include "SkyEyePublicHeader.h"

MYSQL DbObj;  //handle
int connect_stat = 0;
int load_database()
{
	MYSQL_RES *pRes; //result
	MYSQL_ROW  sqlrow; //row
	char strsql[200];
	char username[20];
	char password[20];

	sprintf(username,DB_USERNAME);
	sprintf(password,DB_PASSWORD);
	
	if(connect_stat)	//if connect already exist, clear memory
	{
		unload_database();
	}

	mysql_init(&DbObj);
	printf("Connecting....\n");

	if(!mysql_real_connect(&DbObj, DB_ADDRESS, username, password, DB_NAME, DB_PORT, NULL, CLIENT_SSL) )
	{
		printf("Error %u: %s\n", mysql_errno(&DbObj), mysql_error(&DbObj));
		return 0;
	}
	char value = 1;
	mysql_options(&DbObj, MYSQL_OPT_RECONNECT, &value);	//Set this connection reconnectable


	printf("Connect Database Successfully!:)\n");
	connect_stat = 1;

	return 0;
}

int unload_database()
{
		mysql_close(&DbObj);
}

int insert_information_test(char * orgIP, char * desIP, int orgPort, int desPort, char * package, int length)
{
	char insert_string[2048] = {0};
	char * end;
	sprintf(insert_string, "insert into skyeye_sensitive_info (sOriIp, sDesIp, iOriPort, iDesPort, varPackage) values (\"%s\", \"%s\", %d, %d, ",
		orgIP, desIP, orgPort, desPort
		);
	printf("%s\n", insert_string);

	if(length > 1500) length = 1500;

	end = insert_string + strlen(insert_string);
    *end++ = '\'';
    end += mysql_real_escape_string(&DbObj, end,(char *)package, length * sizeof(char));
    *end++ = '\'';
    *end++ = ')';

	mysql_ping(&DbObj);	//Test connection state and if lost we do reconnect
	if(mysql_real_query(&DbObj, insert_string, (unsigned int)(end - insert_string)))
	{
		printf("Error %u: %s\n", mysql_errno(&DbObj), mysql_error(&DbObj));

		switch(mysql_errno(&DbObj))
		{
		case 2006:			//Mysql server has gone away
			load_database();
		}
	}
	return 0;
}

int insert_information_test_string(char * orgIP, char * desIP, int orgPort, int desPort, char * keyword, char * package, int length)
{
	char insert_string[2048] = {0};
	char * end;
	if(!check_string(package, length))
		return 0;
	sprintf(insert_string, "insert into skyeye_sensitive_info (sOriIp, sDesIp, iOriPort, iDesPort, sKeyword, varPackage) values (\"%s\", \"%s\", %d, %d, \"%s\", \"",
		orgIP, desIP, orgPort, desPort, keyword
		);

	memcpy(insert_string + strlen(insert_string), package, length>1500?1500:length);
	strcat(insert_string + strlen(insert_string), "\")");
	//printf("%s\n", insert_string);

	mysql_ping(&DbObj);	//Test connection state and if lost we do reconnect
	if(mysql_real_query(&DbObj, insert_string, strlen(insert_string)))
	{
		printf("Error %u: %s\n", mysql_errno(&DbObj), mysql_error(&DbObj));

		switch(mysql_errno(&DbObj))
		{
		case 2006:			//Mysql server has gone away
			load_database();
		}
	}
	return 0;
}

int check_string(char * packet, int length)
{
	int i = 0;
	for(i = 0; i < length; i++)
	{
		if(!(
			(*(packet + i) >= 32 && *(packet + i) <= 127) || (*(packet + i) > 6 && *(packet + i) < 14)
			))
		{
			break;
		}
	}
	if( i != length )
	{
		printf("string check failed. %d\n", i);
		return 0;
	}
	else
	{
		printf("string check pass. %d\n", i);
		return 1;
	}
}