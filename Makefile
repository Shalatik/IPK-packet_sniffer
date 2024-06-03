# Project: VUT FIT IPK 2.projekt
# Author: Simona Ceskova xcesko00
# Date: 24.04.2022

TARGET = ipk-sniffer
CFLAGS = -g -Wall
CC = g++

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).cpp -lpcap
clean:
	rm $(TARGET)