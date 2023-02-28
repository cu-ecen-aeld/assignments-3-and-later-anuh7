CC = gcc
CROSS_COMPILE =
CFLAGS := -g -Wall -Werror
LDFLAGS := -pthread
TARGET = aesdsocket


all:	aesdsocket.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -o $(TARGET) aesdsocket.c $(LDFLAGS)

clean:
	-rm -f *.o $(TARGET) *.elf *.map
