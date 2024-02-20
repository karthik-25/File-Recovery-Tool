CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra
LDFLAGS=-lcrypto

.PHONY: all
all: file-rec

file-rec: file-rec.o

file-rec.o: file-rec.c

.PHONY: clean
clean:
	rm -f *.o file-rec
