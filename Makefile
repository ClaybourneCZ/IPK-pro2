#
# 
#  Author: Vaclav Chadim (xchadi09)
#  IPK Project 2
#  Network Sniffer
#  
#  WSL - Ubuntu 20.04
#

CC = gcc
CFLAGS = -pedantic -lpcap -Wall -Wextra

all: prints.o filterBuilder.o main.o ipk-sniffer

prints.o: prints.c prints.h
	$(CC) $(CFLAGS) -c prints.c -lpcap	

filterBuilder.o: filterBuilder.c filterBuilder.h
	$(CC) $(CFLAGS) -c filterBuilder.c -lpcap	

main.o: main.c 
	$(CC) $(CFLAGS) -c main.c -lpcap

ipk-sniffer: main.c 
	$(CC) $(CFLAGS) filterBuilder.o prints.o main.o  -o ipk-sniffer -lpcap



clean:
	rm prints.o filterBuilder.o main.o ipk-sniffer