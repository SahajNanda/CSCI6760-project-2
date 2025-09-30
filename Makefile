# Makefile for http_downloader project file(s)

CC = gcc
CFLAGS = -Wall -02
LDFLAGS = -lssl -lcrypto -lpthread

TARGET = http_downloader
SRC = http_downloader.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) part_* *.o