#Makefile

CC = gcc

chiprodump : chiprodump.c
	gcc chiprodump.c -o chiprodump -lpcap

$(chmod +x ./chiprodump)


clean:
	rm *.o chiprodump.out
