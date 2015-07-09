OBJS = SkyEyeSnifferClient.o SkyEyeSnifferDatabase.o SkyEyeSnifferPolicy.o
CC = gcc
CFLAGES  = -Wall -lpcap -lmysqlclient -g
RM = rm -f

executable: $(OBJS)
	$(CC) $(OBJS) -o SkyEyeSnifferClient -lpcap -lmysqlclient

SkyEyeSnifferClient.o : SkyEyeSnifferClient.c SkyEyePublicHeader.h SkyEyeSnifferClient.h  /usr/local/include/pcap/pcap.h
	$(CC) -c $< -o $@

SkyEyeSnifferDatabase.o : SkyEyeSnifferDatabase.c SkyEyePublicHeader.h SkyEyeSnifferDatabase.h /usr/include/mysql/mysql.h 
	$(CC) -c $< -o $@

SkyEyeSnifferPolicy.o : SkyEyeSnifferPolicy.c SkyEyePublicHeader.h SkyEyeSnifferPolicy.h 
	$(CC) -c $< -o $@

clean :
	$(RM) *.o