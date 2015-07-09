#include "SkyEyePublicHeader.h"
/*function define start*/

int load_database();

int insert_information_test(char * orgIP, char * desIP, int orgPort, int desPort,  char * package, int length);

int insert_information_test_string(char * orgIP, char * desIP, int orgPort, int desPort, char * keyword, char * package, int length);

int check_string(char * packet, int length);
/*function define end*/
